"""联调“真实 TCP 客户端”：手工拆字节构造 WebSocket 帧，不使用任何引擎。

这个模块刻意不依赖任何 WebSocket 库——所有帧头、掩码、扩展载荷长度、
分片、压缩标记都是直接拼字节，才能模拟畸形帧与竞态。
"""
from __future__ import annotations

import base64
import os
import socket
import struct
import zlib

OP_CONT = 0x0
OP_TEXT = 0x1
OP_BINARY = 0x2
OP_CLOSE = 0x8
OP_PING = 0x9
OP_PONG = 0xA

TRAILER = b"\x00\x00\xff\xff"


class RawSocketClosed(Exception):
    pass


class RawWS:
    def __init__(self, sock: socket.socket):
        self.sock = sock
        self.buf = b""

    # ----------------------- 底层读写 -----------------------
    def recv_exact(self, n: int) -> bytes:
        while len(self.buf) < n:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise RawSocketClosed("EOF")
            self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out

    def recv_some(self) -> bytes:
        chunk = self.sock.recv(65536)
        if not chunk:
            raise RawSocketClosed("EOF")
        self.buf += chunk
        out, self.buf = self.buf, b""
        return out

    # ----------------------- HTTP 握手 -----------------------
    def handshake(
        self,
        extra_headers: dict[str, str] | None = None,
        mutate: bytes | None = None,
        deflate: bool = False,
    ) -> bytes:
        key = base64.b64encode(os.urandom(16))
        headers = {
            "Host": "localhost",
            "Upgrade": "websocket",
            "Connection": "Upgrade",
            "Sec-WebSocket-Key": key.decode(),
            "Sec-WebSocket-Version": "13",
        }
        if deflate:
            headers["Sec-WebSocket-Extensions"] = (
                "permessage-deflate; client_max_window_bits"
            )
        if extra_headers:
            headers.update(extra_headers)

        if mutate is None:
            req = b"GET /echo HTTP/1.1\r\n"
            for k, v in headers.items():
                req += f"{k}: {v}\r\n".encode()
            req += b"\r\n"
        else:
            req = mutate  # 完全畸形的请求，原样发送
        self.sock.sendall(req)

        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RawSocketClosed("EOF during handshake: " + resp.decode("latin1", "replace"))
            resp += chunk
        head, _, leftover = resp.partition(b"\r\n\r\n")
        self.buf += leftover
        return head

    # ----------------------- 手工构帧 -----------------------
    @staticmethod
    def build_frame(
        opcode: int,
        payload: bytes = b"",
        fin: bool = True,
        rsv1: bool = False,
        rsv2: bool = False,
        rsv3: bool = False,
        masked: bool = True,
        mask_key: bytes | None = None,
    ) -> bytes:
        """逐字节拼 RFC 6455 帧头，允许制造任何畸形组合。"""
        b0 = (
            (0x80 if fin else 0)
            | (0x40 if rsv1 else 0)
            | (0x20 if rsv2 else 0)
            | (0x10 if rsv3 else 0)
            | (opcode & 0x0F)
        )
        length = len(payload)
        if length < 126:
            head = bytes([b0, length | (0x80 if masked else 0)])
        elif length <= 0xFFFF:
            head = bytes([b0, 126 | (0x80 if masked else 0)]) + struct.pack("!H", length)
        else:
            head = bytes([b0, 127 | (0x80 if masked else 0)]) + struct.pack("!Q", length)

        if masked:
            if mask_key is None:
                mask_key = os.urandom(4)
            head += mask_key
            payload = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))
        return head + payload

    def send_frame(self, *args, **kwargs) -> None:
        self.sock.sendall(self.build_frame(*args, **kwargs))

    def send_ping(self, data: bytes = b"") -> None:
        self.send_frame(OP_PING, data)

    def send_pong(self, data: bytes = b"") -> None:
        self.send_frame(OP_PONG, data)

    def send_close(self, code: int | None = None, reason: bytes = b"") -> None:
        if code is None:
            payload = b""
        else:
            payload = struct.pack("!H", code) + reason
        self.send_frame(OP_CLOSE, payload)

    # ----------------------- 手工读帧 -----------------------
    def recv_frame(self):
        b0, b1 = self.recv_exact(2)
        fin = bool(b0 & 0x80)
        rsv1 = bool(b0 & 0x40)
        opcode = b0 & 0x0F
        masked = bool(b1 & 0x80)
        length = b1 & 0x7F
        if length == 126:
            length = struct.unpack("!H", self.recv_exact(2))[0]
        elif length == 127:
            length = struct.unpack("!Q", self.recv_exact(8))[0]
        mask = self.recv_exact(4) if masked else b""
        payload = self.recv_exact(length) if length else b""
        if masked:
            payload = bytes(b ^ mask[i & 3] for i, b in enumerate(payload))
        return fin, rsv1, opcode, payload

    def recv_until_close(self, timeout: float = 6.0):
        """返回 (close_code, close_payload, 关闭前收到的非控制帧列表)。"""
        self.sock.settimeout(timeout)
        frames_before = []
        try:
            while True:
                fin, rsv1, opcode, payload = self.recv_frame()
                if opcode == OP_CLOSE:
                    code = struct.unpack("!H", payload[:2])[0] if len(payload) >= 2 else None
                    return code, payload, frames_before
                if opcode < OP_CLOSE:
                    frames_before.append((fin, rsv1, opcode, payload))
                # PING/PONG 跳过
        except RawSocketClosed:
            return None, b"", frames_before

    def close(self) -> None:
        try:
            self.sock.close()
        except OSError:
            pass


def connect(host: str = "127.0.0.1", port: int = 8080) -> RawWS:
    s = socket.create_connection((host, port), timeout=6)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return RawWS(s)


def open_ws(host: str, port: int, deflate: bool = False, **hw) -> RawWS:
    c = connect(host, port)
    head = c.handshake(deflate=deflate, **hw)
    if b"101 Switching Protocols" not in head:
        raise AssertionError(f"handshake failed:\n{head.decode('latin1', 'replace')}")
    return c


# ----------------------- permessage-deflate 辅助 -----------------------
def deflate_message(data: bytes) -> bytes:
    co = zlib.compressobj(zlib.Z_DEFAULT_COMPRESSION, zlib.DEFLATED, -15)
    out = co.compress(data) + co.flush(zlib.Z_SYNC_FLUSH)
    if out.endswith(TRAILER):
        out = out[:-4]
    return out


def inflate_message(data: bytes) -> bytes:
    d = zlib.decompressobj(-15)
    out = d.decompress(data + TRAILER)
    return out


def reassemble(frames_before, expect_deflate: bool) -> bytes:
    """把若干可能分片的回显帧拼成完整消息，RSV1 帧做解压。"""
    chunks = []
    compressed = False
    for fin, rsv1, opcode, payload in frames_before:
        if rsv1:
            payload = inflate_message(payload)
            compressed = True
        chunks.append(payload)
    return b"".join(chunks), compressed
