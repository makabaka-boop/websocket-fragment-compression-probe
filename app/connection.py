"""单条 WebSocket 连接的帧/消息状态机（自行处理 RFC 6455 第 5、7 节）。

关键不变式：
  * 控制帧（Ping/Pong/Close）独立处理，绝不喂进消息缓冲或解压器，
    因此允许插在分片消息中间（§5.5），也不会被提前当作文本交付；
  * 一条消息必须等到 FIN 帧、解压完整、UTF-8（文本）校验通过、
    且总长不超过 16 KiB 后才会回显——任何一步失败都只发 Close，
    绝不产生半条回显；
  * permessage-deflate 的压缩标记（RSV1）只允许出现在消息的首个
    数据帧上，解压尾部 00 00 ff ff 只在 FIN 帧补；
  * 收到 Close 后进入 CLOSING 状态：丢弃分片消息、不再接受任何新的
    业务消息，只回 Close/必要的 Pong，等待对端 FIN 直到关闭期限。
"""
from __future__ import annotations

import asyncio
import contextlib

from .errors import (
    MessageTooLarge,
    ProtocolError,
    TextDecodeError,
    WebSocketError,
)
from .extension import MessageInflater, compress_message
from .framing import (
    BINARY,
    CLOSE,
    CONTINUATION,
    PING,
    PONG,
    TEXT,
    encode_frame,
    read_frame,
)
from .handshake import perform_handshake
from .utf8 import IncrementalUTF8Validator

MAX_MESSAGE = 16 * 1024  # 解压后完整消息硬上限

OPEN = "OPEN"
CLOSING = "CLOSING"
CLOSED = "CLOSED"


def _valid_status(code: int) -> bool:
    """RFC 6455 §7.4.2：允许在线路上出现的状态码。"""
    if code in (1000,):
        return True
    if 1001 <= code <= 1003 or 1007 <= code <= 1011 or 1013 <= code <= 1015:
        return True
    if 3000 <= code <= 4999:
        return True
    return False


def encode_close(code: int | None = None, reason: bytes = b"") -> bytes:
    if code is None:
        payload = b""
    else:
        payload = code.to_bytes(2, "big") + reason
    return encode_frame(CLOSE, payload)


class Connection:
    def __init__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        deflate: bool,
        close_timeout: float,
        peer: tuple | str = "?",
    ) -> None:
        self._reader = reader
        self._writer = writer
        self._deflate = deflate
        self._close_deadline = close_timeout
        self._peer = peer

        self._state = OPEN

        # --- 正在装配的消息状态（控制帧不会触碰这些字段）---
        self._msg_opcode: int | None = None
        self._msg_chunks: list[bytes] = []
        self._msg_size = 0
        self._msg_compress = False
        self._inflater: MessageInflater | None = None
        self._validator = IncrementalUTF8Validator()

    async def run(self) -> None:
        try:
            while self._state == OPEN:
                frame = await read_frame(self._reader)
                await self._dispatch_open(frame)
        except asyncio.IncompleteReadError:
            # 对端在握手/读帧中途直接断开，无 Close 可回
            self._state = CLOSED
        except WebSocketError as exc:
            await self._fail(exc)
        except ConnectionError:
            self._state = CLOSED
        finally:
            await self._shutdown_writer()

    # ------------------------------------------------------------------
    # OPEN 状态下的帧分派
    # ------------------------------------------------------------------
    async def _dispatch_open(self, frame) -> None:
        # RSV2/RSV3 没有任何协商过的含义，任何帧上出现都是协议错误
        if frame.rsv2 or frame.rsv3:
            raise ProtocolError("unnegotiated RSV2/RSV3 bit")

        if frame.opcode >= CLOSE:
            # 控制帧不允许携带压缩标记（RFC 7692：RSV1 只属于数据帧）
            if frame.rsv1:
                raise ProtocolError("RSV1 on control frame")
            await self._handle_control(frame)
            return

        # ----- 数据帧 / 延续帧 -----
        if frame.opcode in (TEXT, BINARY):
            if self._msg_opcode is not None:
                # 上一条消息还没收完又来了首帧
                raise ProtocolError("new message started before FIN")
            if not self._deflate and frame.rsv1:
                # 未协商压缩却收到压缩位
                raise ProtocolError("RSV1 set without permessage-deflate")
            self._msg_opcode = frame.opcode
            self._msg_compress = frame.rsv1
            self._msg_chunks = []
            self._msg_size = 0
            if frame.opcode == TEXT:
                self._validator.reset()
            if self._msg_compress:
                self._inflater = MessageInflater(MAX_MESSAGE)
        elif frame.opcode == CONTINUATION:
            if self._msg_opcode is None:
                raise ProtocolError("continuation without start frame")
            if frame.rsv1:
                # 压缩标记只属于首个数据帧
                raise ProtocolError("RSV1 on continuation frame")
        else:  # read_frame 已拦保留 opcode，此处防御
            raise ProtocolError("reserved opcode")

        await self._append_data(frame)

        if frame.fin:
            await self._finish_message()

    async def _append_data(self, frame) -> None:
        if self._msg_compress:
            assert self._inflater is not None
            try:
                if frame.fin:
                    piece = self._inflater.finish(frame.payload)
                else:
                    piece = self._inflater.feed(frame.payload)
            except ProtocolError:
                raise  # 损坏压缩流 -> 1002
        else:
            piece = frame.payload

        self._msg_size += len(piece)
        if self._msg_size > MAX_MESSAGE:
            raise MessageTooLarge("message exceeds 16 KiB")

        if self._msg_opcode == TEXT:
            # 跨分片保持连续：不完整的多字节序列留在校验器里
            self._validator.feed(piece)

        self._msg_chunks.append(piece)

    async def _finish_message(self) -> None:
        opcode = self._msg_opcode
        assert opcode is not None
        chunks = self._msg_chunks
        compress = self._msg_compress

        if opcode == TEXT:
            # 消息结束才判定截断序列；至此全部 UTF-8 校验通过
            self._validator.finish()

        message = b"".join(chunks)  # 解压后、且 <=16 KiB
        self._reset_message()

        # 全部校验通过才回显，且一次性发完整帧（无半条回显）
        if self._deflate:
            payload = compress_message(message)
            self._write(encode_frame(opcode, payload, rsv1=True))
        else:
            self._write(encode_frame(opcode, message))
        await self._drain()

    def _reset_message(self) -> None:
        self._msg_opcode = None
        self._msg_chunks = []
        self._msg_size = 0
        self._msg_compress = False
        self._inflater = None
        self._validator.reset()

    # ------------------------------------------------------------------
    # 控制帧
    # ------------------------------------------------------------------
    async def _handle_control(self, frame) -> None:
        if frame.opcode == PING:
            # §5.5.2：原样回 Pong；插在分片消息中间也不能影响装配
            self._write(encode_frame(PONG, frame.payload))
            await self._drain()
        elif frame.opcode == PONG:
            # §5.5.3：对 Pong 不做任何响应；非请求的 Pong 直接忽略
            return
        elif frame.opcode == CLOSE:
            await self._begin_closing(frame.payload)

    async def _begin_closing(self, payload: bytes) -> None:
        # RFC 6455 §5.5.1 / §7.1.6 解析关闭帧
        status: int | None = None
        reason = b""
        if len(payload) == 1:
            raise ProtocolError("close frame with 1-byte payload")
        if len(payload) >= 2:
            status = int.from_bytes(payload[:2], "big")
            reason = payload[2:]
            if not _valid_status(status):
                raise ProtocolError("invalid close status code")
            try:
                reason.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise TextDecodeError("close reason is not utf-8") from exc

        # 丢弃正在装配的半成品消息（绝不回显），随后回 Close
        self._reset_message()
        self._state = CLOSING
        self._write(encode_close(status, reason))
        await self._drain()

        # 等待对端的 Close/FIN，受关闭期限约束；期间不接受新业务消息
        try:
            await asyncio.wait_for(self._drain_until_peer_close(), self._close_deadline)
        except (TimeoutError, asyncio.TimeoutError, WebSocketError, asyncio.IncompleteReadError):
            pass
        self._state = CLOSED

    async def _drain_until_peer_close(self) -> None:
        while True:
            frame = await read_frame(self._reader)
            if frame.rsv2 or frame.rsv3 or (frame.rsv1 and frame.opcode >= CLOSE):
                raise ProtocolError("bad RSV during closing")
            if frame.opcode == CLOSE:
                return  # 对端完成关闭握手
            if frame.opcode == PING:
                self._write(encode_frame(PONG, frame.payload))
                await self._drain()
            # Pong 与数据帧一律忽略：Close 开始后无新业务消息

    # ------------------------------------------------------------------
    # 错误 / 收尾
    # ------------------------------------------------------------------
    async def _fail(self, exc: WebSocketError) -> None:
        if self._state == CLOSED:
            return
        self._reset_message()
        self._state = CLOSING
        # 主动关闭：坏帧 1002 / 坏文本 1007 / 过大 1009（损坏压缩流归 1002）
        self._write(encode_close(exc.code, exc.reason.encode("utf-8")))
        with contextlib.suppress(Exception):
            await self._drain()
        try:
            await asyncio.wait_for(
                self._drain_until_peer_close(), self._close_deadline
            )
        except (TimeoutError, asyncio.TimeoutError, asyncio.IncompleteReadError):
            pass
        except Exception:
            pass
        self._state = CLOSED

    # ------------------------------------------------------------------
    def _write(self, data: bytes) -> None:
        self._writer.write(data)

    async def _drain(self) -> None:
        await self._writer.drain()

    async def _shutdown_writer(self) -> None:
        if self._writer.is_closing():
            return
        with contextlib.suppress(Exception):
            await self._writer.drain()
        self._writer.close()
        with contextlib.suppress(Exception):
            await self._writer.wait_closed()


async def handle_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    close_timeout: float,
) -> None:
    peer = writer.get_extra_info("peername") or "?"
    try:
        result = await perform_handshake(reader, writer)
    except ProtocolError:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
        return
    except (ConnectionError, asyncio.IncompleteReadError):
        writer.close()
        return

    conn = Connection(
        reader,
        writer,
        deflate=result.deflate,
        close_timeout=close_timeout,
        peer=peer,
    )
    await conn.run()
