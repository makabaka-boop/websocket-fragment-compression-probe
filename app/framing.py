"""手工实现的 RFC 6455 §5.2 帧编解码。

服务端视角：客户端发来的每一帧必须带掩码（MASK=1），否则按协议错误 1002
关闭；服务端发出的帧一律不掩码。本模块只负责“字节 <-> 帧对象”的翻译，
不维护任何消息级状态（分片、压缩等由 connection.py 处理）。
"""
from __future__ import annotations

import asyncio
import struct

from .errors import MessageTooLarge, ProtocolError

# RFC 6455 §5.2 操作码
CONTINUATION = 0x0
TEXT = 0x1
BINARY = 0x2
# 0x3-0x7 保留（非控制），收到即协议错误
CLOSE = 0x8
PING = 0x9
PONG = 0xA
# 0xB-0xF 保留（控制），收到即协议错误

# 控制帧载荷硬上限：RFC 6455 §5.5，超过即协议错误
CONTROL_MAX_PAYLOAD = 125
# 单帧声明载荷长度上限。解压后另有 16 KiB 消息上限，但仍需拒绝明显
# 超大的帧声明，避免无界缓冲；超出按“消息过大”1009 处理。
FRAME_MAX_PAYLOAD = 1024 * 1024

# 7 位载荷长度字段的两个转义值
LEN_16BIT = 126
LEN_64BIT = 127


class Frame:
    __slots__ = ("fin", "rsv1", "rsv2", "rsv3", "opcode", "payload")

    def __init__(
        self,
        opcode: int,
        payload: bytes = b"",
        fin: bool = True,
        rsv1: bool = False,
        rsv2: bool = False,
        rsv3: bool = False,
    ):
        self.fin = fin
        self.rsv1 = rsv1
        self.rsv2 = rsv2
        self.rsv3 = rsv3
        self.opcode = opcode
        self.payload = payload

    def __repr__(self) -> str:  # pragma: no cover - 调试用
        return (
            f"Frame(op={self.opcode:#x}, fin={self.fin}, "
            f"rsv=({int(self.rsv1)},{int(self.rsv2)},{int(self.rsv3)}), "
            f"len={len(self.payload)})"
        )


async def read_frame(reader: asyncio.StreamReader) -> Frame:
    """从流中精确读取一个客户端帧，完成长度校验与解掩码。"""
    head = await reader.readexactly(2)
    b0, b1 = head[0], head[1]

    fin = bool(b0 & 0x80)
    rsv1 = bool(b0 & 0x40)
    rsv2 = bool(b0 & 0x20)
    rsv3 = bool(b0 & 0x10)
    opcode = b0 & 0x0F

    masked = bool(b1 & 0x80)
    length = b1 & 0x7F

    # 扩展载荷长度（big-endian）
    if length == LEN_16BIT:
        ext = await reader.readexactly(2)
        length = struct.unpack("!H", ext)[0]
        if length < 126:
            # RFC 6455 §5.2：必须使用最短编码
            raise ProtocolError("non-minimal frame length")
    elif length == LEN_64BIT:
        ext = await reader.readexactly(8)
        length = struct.unpack("!Q", ext)[0]
        if length < 65536:
            raise ProtocolError("non-minimal frame length")

    opcode_valid = opcode in (
        CONTINUATION,
        TEXT,
        BINARY,
        CLOSE,
        PING,
        PONG,
    )
    if not opcode_valid:
        raise ProtocolError("reserved opcode")

    is_control = opcode >= CLOSE
    if is_control:
        if not fin:
            # §5.5：控制帧不得分片
            raise ProtocolError("fragmented control frame")
        if length > CONTROL_MAX_PAYLOAD:
            raise ProtocolError("control frame payload exceeds 125")
    if length > FRAME_MAX_PAYLOAD:
        # 声明长度大到无意义；解压后超限是 1009，原始帧声明同样按过大处理
        raise MessageTooLarge("frame payload exceeds hard limit")

    # 客户端帧必须带掩码（§5.1）
    if not masked:
        raise ProtocolError("client frame is not masked")
    mask = await reader.readexactly(4)

    payload = await reader.readexactly(length)
    unmasked = bytearray(length)
    for i in range(length):
        unmasked[i] = payload[i] ^ mask[i & 3]

    return Frame(
        opcode,
        bytes(unmasked),
        fin=fin,
        rsv1=rsv1,
        rsv2=rsv2,
        rsv3=rsv3,
    )


def encode_frame(
    opcode: int,
    payload: bytes | bytearray = b"",
    fin: bool = True,
    rsv1: bool = False,
) -> bytes:
    """编码一个服务端帧（不掩码，服务端从不掩码）。"""
    b0 = (0x80 if fin else 0) | (0x40 if rsv1 else 0) | opcode

    length = len(payload)
    if length < 126:
        out = bytes([b0, length])
    elif length <= 0xFFFF:
        out = struct.pack("!BBH", b0, LEN_16BIT, length)
    else:
        out = struct.pack("!BBQ", b0, LEN_64BIT, length)
    return out + bytes(payload)
