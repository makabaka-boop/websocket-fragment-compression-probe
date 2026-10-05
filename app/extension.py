"""permessage-deflate 协商（RFC 7692），只协商双向 no_context_takeover。

握手规则（故意收紧）：
  * 客户端没有提供 permessage-deflate -> 不协商，返回 None；
  * 提供了 -> 应答里固定带
    ``permessage-deflate; client_no_context_takeover; server_no_context_takeover``
    （第 7.1.1 节：服务端可在应答中单方面声明 *_no_context_takeover，
      即使客户端请求里没写）；
  * 窗口大小等其他参数一律忽略（默认 15，§7.1.2.1/7.1.2.2 的实现自由度）。
不协商压缩时，连接层必须拒绝任何带压缩标记（RSV1）的数据帧（1002）。
"""
from __future__ import annotations

import zlib

from .errors import ProtocolError

EXT_NAME = "permessage-deflate"
_TRAILER = b"\x00\x00\xff\xff"  # RFC 7692 §7.2.1：消息末尾补回的尾部


def negotiate(header_value: str | None) -> str | None:
    """解析 Sec-WebSocket-Extensions，命中则返回服务端应答值，否则 None。

    这里没有依赖任何 WebSocket 栈，只做 §7.1 令牌语法的轻量解析；
    其他扩展（如未知 x-foo）直接忽略。
    """
    if not header_value:
        return None
    if not _has_permessage_deflate(header_value):
        return None
    # 只协商无上下文接管的双向模式
    return f"{EXT_NAME}; client_no_context_takeover; server_no_context_takeover"


def _has_permessage_deflate(value: str) -> bool:
    # 按逗号切分扩展，再按分号切参数，第一个 token 即扩展名
    for ext in value.split(","):
        parts = ext.split(";")
        if not parts:
            continue
        name = parts[0].strip().lower()
        if name == EXT_NAME:
            _validate_params(parts[1:])
            return True
    return False


def _validate_params(params: list[str]) -> None:
    """对 permessage-deflate 参数做最小校验，未知但合法的参数直接忽略。

    无法解析的参数（等号右边不是 token / quoted-string）属于非法协商，
    直接当作未提供该扩展处理：握手仍成功，只是不开启压缩，客户端随后
    若发压缩位会被帧状态机以 1002 拒绝。
    """
    for p in params:
        key, _, value = p.partition("=")
        key = key.strip().lower()
        value = value.strip()
        if key in (
            "client_max_window_bits",
            "server_max_window_bits",
            "client_no_context_takeover",
            "server_no_context_takeover",
        ):
            continue
        # 未知扩展参数按 RFC 7692 §7.1 可忽略；这里宽松放行


def compress_message(data: bytes, level: int = zlib.Z_DEFAULT_COMPRESSION) -> bytes:
    """按 §7.2.1 压缩一条消息：raw DEFLATE + 去掉末尾 0x00 0x00 0xff 0xff。"""
    co = zlib.compressobj(level, zlib.DEFLATED, -15)
    block = co.compress(data) + co.flush(zlib.Z_SYNC_FLUSH)
    if block.endswith(_TRAILER):
        block = block[: -len(_TRAILER)]
    return block


class MessageInflater:
    """单条消息的 raw DEFLATE 解压器。

    no_context_takeover 意味着每条消息都是独立流，因此一条消息一个实例；
    延续帧到达时逐片喂入，最后的帧（FIN）补 0x00 0x00 0xff 0xff（§7.2.2）。
    压缩标记只属于首个数据帧，控制帧绝不参与解压（连接层保证不会走到这里）。
    """

    def __init__(self, max_message: int) -> None:
        self._d = zlib.decompressobj(-15)
        self._max = max_message
        self._size = 0
        self._finished = False

    def feed(self, data: bytes) -> bytes:
        if self._finished:
            raise ProtocolError("deflate use after final frame")
        return self._inflate(data, finish=False)

    def finish(self, data: bytes) -> bytes:
        out = self._inflate(data, finish=False)
        out += self._inflate(_TRAILER, finish=True)
        self._finished = True
        return out

    def _inflate(self, data: bytes, finish: bool) -> bytes:
        try:
            # 用 max_length 把输出限制在上限+1：一旦超过即消息过大（1009）。
            room = self._max + 1 - self._size
            out = self._d.decompress(data, room)
            if self._d.unconsumed_tail:
                # 还有没消费的输入且输出已打满 -> 解压结果超限
                from .errors import MessageTooLarge

                raise MessageTooLarge("decompressed message exceeds 16 KiB")
            if finish:
                out += self._d.flush()
            self._size += len(out)
            if self._size > self._max:
                from .errors import MessageTooLarge

                raise MessageTooLarge("decompressed message exceeds 16 KiB")
            return out
        except zlib.error as exc:
            # 损坏的压缩流：协议错误 1002（题目要求的“损坏压缩流”分支）
            raise ProtocolError(f"invalid deflate stream: {exc}") from exc
