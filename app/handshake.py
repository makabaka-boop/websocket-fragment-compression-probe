"""WebSocket 升级握手（RFC 6455 §4.2）。

HTTP 解析复用成熟的标准库组件：请求行由本模块按字节切分（语法极简，
且要能精确区分各类拒绝原因），头部解析使用标准库 ``http.client`` 的
``parse_headers``（基于 email.parser 的成熟 HTTP 头解析器）。握手通过后
交给自行实现的 RFC 6455 帧/消息状态机，任何 WebSocket 栈都不参与。
"""
from __future__ import annotations

import asyncio
import base64
import binascii
import hashlib
from http.client import parse_headers
from io import BytesIO

from .errors import ProtocolError
from .extension import negotiate

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_HEADER_BLOCK = 65536
WS_VERSION = "13"


class HandshakeResult:
    def __init__(self, extensions_header: str | None, deflate: bool):
        # 服务端应答使用的 Sec-WebSocket-Extensions 值（None 表示不压缩）
        self.extensions_header = extensions_header
        self.deflate = deflate


def bad_request(msg: bytes = b"Bad Request") -> bytes:
    body = msg + b"\n"
    return (
        b"HTTP/1.1 400 Bad Request\r\n"
        b"Content-Type: text/plain; charset=utf-8\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n" + body
    )


def _check_key(key: str) -> bool:
    # §4.2.1.1：16 字节随机值的 base64（带/不带填充都可能，长度 22..24）
    try:
        raw = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError):
        return False
    return len(raw) == 16


async def perform_handshake(
    reader: asyncio.StreamReader, writer: asyncio.StreamWriter
) -> HandshakeResult:
    """读取并校验升级请求，成功则写回 101；失败发送 400 并抛 ProtocolError。

    返回后 reader 中可能已经缓存了 WebSocket 帧（管线化数据），由连接层
    继续从同一个 reader 读取，不丢字节。
    """
    try:
        # readuntil 在找不到分隔符且超出 limit 时会抛 LimitOverrunError
        block = await reader.readuntil(b"\r\n\r\n")
    except (asyncio.LimitOverrunError, asyncio.IncompleteReadError) as exc:
        writer.write(bad_request(b"header block too large or incomplete"))
        await writer.drain()
        raise ProtocolError("handshake header block invalid") from exc

    if len(block) > MAX_HEADER_BLOCK:
        writer.write(bad_request())
        await writer.drain()
        raise ProtocolError("handshake header block too large")

    header_end = block.find(b"\r\n\r\n")
    message = block[:header_end]
    lines = message.split(b"\r\n")

    request_line = lines[0].split(b" ")
    if len(request_line) != 3 or request_line[0] != b"GET" or request_line[2] not in (
        b"HTTP/1.1",
        b"HTTP/1.0",
    ):
        writer.write(bad_request(b"Expected GET HTTP/1.1"))
        await writer.drain()
        raise ProtocolError("invalid request line")

    # 成熟组件负责头部字段解析（折叠、空白、重复头等由标准库处理）
    header_stream = BytesIO(b"\r\n".join(lines[1:]) + b"\r\n")
    try:
        headers = parse_headers(header_stream)
    except Exception as exc:  # 标准库对畸形头会抛 HTTPException 等
        writer.write(bad_request())
        await writer.drain()
        raise ProtocolError("malformed http headers") from exc

    def h(name: str) -> str | None:
        return headers.get(name)

    upgrade = (h("Upgrade") or "").lower()
    connection = (h("Connection") or "").lower()
    key = h("Sec-WebSocket-Key")
    version = h("Sec-WebSocket-Version")

    def has_connection_token(token: str) -> bool:
        return any(t.strip() == token for t in connection.split(","))

    if not key or not _check_key(key):
        writer.write(bad_request(b"Invalid Sec-WebSocket-Key"))
        await writer.drain()
        raise ProtocolError("invalid sec-websocket-key")
    if version != WS_VERSION:
        # §4.4：版本不对要在 400 里回 Sec-WebSocket-Version: 13
        body = b"Upgrade Required\n"
        writer.write(
            b"HTTP/1.1 426 Upgrade Required\r\n"
            b"Sec-WebSocket-Version: 13\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        await writer.drain()
        raise ProtocolError("unsupported websocket version")
    if "websocket" not in upgrade or not has_connection_token("upgrade"):
        writer.write(bad_request(b"Expected Upgrade: websocket"))
        await writer.drain()
        raise ProtocolError("missing upgrade tokens")

    extensions_header = negotiate(h("Sec-WebSocket-Extensions"))
    deflate = extensions_header is not None

    accept = base64.b64encode(
        hashlib.sha1((key + GUID).encode()).digest()
    ).decode()
    response = (
        b"HTTP/1.1 101 Switching Protocols\r\n"
        b"Upgrade: websocket\r\n"
        b"Connection: Upgrade\r\n"
        b"Sec-WebSocket-Accept: " + accept.encode() + b"\r\n"
    )
    if extensions_header is not None:
        response += b"Sec-WebSocket-Extensions: " + extensions_header.encode() + b"\r\n"
    response += b"\r\n"
    writer.write(response)
    await writer.drain()

    return HandshakeResult(extensions_header, deflate)
