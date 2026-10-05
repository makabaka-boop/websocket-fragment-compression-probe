#!/usr/bin/env python3
"""Raw-TCP test suite for ws_echo_server.

Every frame is hand-built and hand-parsed byte by byte; no WebSocket client
library is used anywhere. Each test opens a fresh TCP connection and performs
a manual HTTP Upgrade handshake.

Usage: python3 test_ws_echo.py [--host H] [--port P] [--close-deadline-ms MS]
"""

from __future__ import annotations

import argparse
import base64
import os
import socket
import struct
import sys
import time
import zlib

OP_CONT, OP_TEXT, OP_BINARY = 0x0, 0x1, 0x2
OP_CLOSE, OP_PING, OP_PONG = 0x8, 0x9, 0xA

MASK_KEY = b"\x5a\xa5\x0f\xf0"
MAX_MESSAGE = 16 * 1024


class TestFailure(Exception):
    pass


def check(cond, msg):
    if not cond:
        raise TestFailure(msg)


# --------------------------------------------------------------- frame kit

def build_frame(opcode, payload=b"", fin=True, rsv1=False, masked=True,
                mask_key=MASK_KEY):
    b1 = (0x80 if fin else 0) | (0x40 if rsv1 else 0) | opcode
    n = len(payload)
    m = 0x80 if masked else 0
    if n < 126:
        hdr = struct.pack("!BB", b1, m | n)
    elif n <= 0xFFFF:
        hdr = struct.pack("!BBH", b1, m | 126, n)
    else:
        hdr = struct.pack("!BBQ", b1, m | 127, n)
    if not masked:
        return hdr + payload
    return hdr + mask_key + bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))


def recv_exact(sock, n):
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"TCP EOF after {len(buf)}/{n} bytes")
        buf += chunk
    return bytes(buf)


def read_frame(sock):
    """Parse one server->client frame (expected unmasked)."""
    b1, b2 = recv_exact(sock, 2)
    fin = bool(b1 & 0x80)
    rsv1 = bool(b1 & 0x40)
    check(not (b1 & 0x30), f"server set RSV2/RSV3 (b1={b1:#x})")
    opcode = b1 & 0x0F
    masked = bool(b2 & 0x80)
    length = b2 & 0x7F
    if length == 126:
        (length,) = struct.unpack("!H", recv_exact(sock, 2))
    elif length == 127:
        (length,) = struct.unpack("!Q", recv_exact(sock, 8))
    mask_key = recv_exact(sock, 4) if masked else b""
    payload = recv_exact(sock, length) if length else b""
    if masked:
        payload = bytes(b ^ mask_key[i & 3] for i, b in enumerate(payload))
    return {"fin": fin, "rsv1": rsv1, "opcode": opcode, "payload": payload}


def pmd_compress(data: bytes) -> bytes:
    """Client-side permessage-deflate: raw DEFLATE, sync-flush, strip tail."""
    c = zlib.compressobj(6, zlib.DEFLATED, -15)
    out = c.compress(data) + c.flush(zlib.Z_SYNC_FLUSH)
    assert out.endswith(b"\x00\x00\xff\xff")
    return out[:-4]


# ------------------------------------------------------------ connection

class Conn:
    def __init__(self, cfg, extensions=None):
        self.cfg = cfg
        self.sock = socket.create_connection((cfg.host, cfg.port), timeout=5)
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [
            "GET /chat HTTP/1.1",
            f"Host: {cfg.host}:{cfg.port}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        if extensions:
            lines.append(f"Sec-WebSocket-Extensions: {extensions}")
        self.sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            chunk = self.sock.recv(4096)
            check(chunk, "TCP EOF during handshake")
            resp += chunk
        head, _, rest = resp.partition(b"\r\n\r\n")
        check(rest == b"", f"unexpected bytes after handshake: {rest!r}")
        parts = head.decode("latin1").split("\r\n")
        check(" 101 " in parts[0], f"handshake rejected: {parts[0]}")
        self.headers = {}
        for line in parts[1:]:
            k, _, v = line.partition(":")
            self.headers[k.strip().lower()] = v.strip()

    def send(self, *frames):
        for fr in frames:
            self.sock.sendall(fr)

    def read(self):
        return read_frame(self.sock)

    def settimeout(self, t):
        self.sock.settimeout(t)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


def expect_data(c, opcode, payload, what="echo"):
    f = c.read()
    check(f["opcode"] == opcode,
          f"{what}: expected opcode {opcode:#x}, got {f['opcode']:#x} "
          f"(payload {f['payload'][:40]!r})")
    check(f["fin"], f"{what}: expected FIN on complete message")
    check(f["payload"] == payload,
          f"{what}: payload mismatch ({len(f['payload'])} vs {len(payload)} bytes): "
          f"{f['payload'][:60]!r} != {payload[:60]!r}")


def expect_close(c, code=None):
    """Read until the server's Close; any business frame before it is a failure
    (guards against half-message echoes)."""
    while True:
        f = c.read()
        if f["opcode"] == OP_CLOSE:
            if code is not None:
                check(len(f["payload"]) >= 2, "close frame without status code")
                (got,) = struct.unpack("!H", f["payload"][:2])
                check(got == code, f"expected close {code}, got {got}")
            return f
        check(f["opcode"] in (OP_PING, OP_PONG),
              f"unexpected frame before close: opcode {f['opcode']:#x} "
              f"payload {f['payload'][:60]!r} (half-message echo?)")


# ------------------------------------------------------------------ tests

def test_basic_text(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_TEXT, b"hello websocket"))
        expect_data(c, OP_TEXT, b"hello websocket")


def test_basic_binary(cfg):
    payload = bytes(range(256)) * 4
    with Conn(cfg) as c:
        c.send(build_frame(OP_BINARY, payload))
        expect_data(c, OP_BINARY, payload)


def test_multiple_messages_one_connection(cfg):
    with Conn(cfg) as c:
        for i in range(5):
            msg = f"message-{i}".encode()
            c.send(build_frame(OP_TEXT, msg))
            expect_data(c, OP_TEXT, msg, f"echo #{i}")


def test_ping_pong(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_PING, b"heartbeat-1"))
        f = c.read()
        check(f["opcode"] == OP_PONG, f"expected pong, got opcode {f['opcode']:#x}")
        check(f["payload"] == b"heartbeat-1", f"pong payload {f['payload']!r}")
        c.send(build_frame(OP_TEXT, b"still alive"))
        expect_data(c, OP_TEXT, b"still alive")


def test_pong_is_ignored(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_PONG, b"unsolicited"),
               build_frame(OP_TEXT, b"next"))
        # if the server answered the pong, the next frame would not be the echo
        expect_data(c, OP_TEXT, b"next")


def test_split_header_byte_by_byte(cfg):
    payload = b"s" * 200  # forces 16-bit extended length
    frame = build_frame(OP_TEXT, payload)
    with Conn(cfg) as c:
        for i in range(len(frame)):  # header, ext-len, mask key: all split
            c.sock.sendall(frame[i:i + 1])
            time.sleep(0.002)
        expect_data(c, OP_TEXT, payload, "byte-by-byte echo")


def test_ping_between_fragments(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_TEXT, "你好，".encode(), fin=False))
        c.send(build_frame(OP_PING, b"mid-message"))
        c.send(build_frame(OP_CONT, "世界".encode(), fin=True))
        f = c.read()
        check(f["opcode"] == OP_PONG and f["payload"] == b"mid-message",
              f"expected pong first, got {f}")
        expect_data(c, OP_TEXT, "你好，世界".encode(), "reassembled echo")


def test_utf8_split_across_fragments(cfg):
    data = "汉字测试，跨帧拆分。".encode()  # every char is 3 bytes
    with Conn(cfg) as c:
        # cut inside the first multi-byte character, then again mid-stream
        c.send(build_frame(OP_TEXT, data[:1], fin=False))      # \xe6
        c.send(build_frame(OP_CONT, data[1:3], fin=False))     # \xb1\x89 -> 汉
        c.send(build_frame(OP_CONT, data[3:7], fin=False))     # split 字? no: 3 bytes + 1
        c.send(build_frame(OP_CONT, data[7:], fin=True))
        expect_data(c, OP_TEXT, data, "utf-8 across fragments")


def test_bad_utf8_no_partial_echo(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_TEXT, b"abc", fin=False))
        c.send(build_frame(OP_CONT, b"\xff\xfe", fin=True))
        expect_close(c, 1007)  # and no "abc" echo may appear before the close


def test_truncated_utf8_at_message_end(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_TEXT, "汉".encode()[:2], fin=True))  # incomplete char
        expect_close(c, 1007)


def test_unmasked_frame_rejected(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_TEXT, b"no mask here", masked=False))
        expect_close(c, 1002)


def test_rsv1_without_negotiation(cfg):
    with Conn(cfg) as c:  # no extension offer
        check("sec-websocket-extensions" not in c.headers,
              "server offered permessage-deflate unprompted")
        c.send(build_frame(OP_TEXT, pmd_compress(b"hi"), rsv1=True))
        expect_close(c, 1002)


def test_fragmented_control_rejected(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_PING, b"x", fin=False))
        expect_close(c, 1002)


def test_oversize_control_rejected(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_PING, b"x" * 126))
        expect_close(c, 1002)


def test_unexpected_continuation_rejected(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_CONT, b"orphan", fin=True))
        expect_close(c, 1002)


def test_interleaved_data_frame_rejected(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_TEXT, b"first", fin=False))
        c.send(build_frame(OP_TEXT, b"second", fin=False))
        expect_close(c, 1002)


def test_reserved_opcode_rejected(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(0xB, b"reserved"))
        expect_close(c, 1002)


def test_pmd_negotiation_and_echo(cfg):
    with Conn(cfg, extensions="permessage-deflate") as c:
        ext = c.headers.get("sec-websocket-extensions", "")
        check("permessage-deflate" in ext, f"missing pmd in response: {ext!r}")
        check("server_no_context_takeover" in ext, f"missing server_no_context_takeover: {ext!r}")
        check("client_no_context_takeover" in ext, f"missing client_no_context_takeover: {ext!r}")
        msg = ("hello compressed world " * 30).encode()
        c.send(build_frame(OP_TEXT, pmd_compress(msg), rsv1=True))
        expect_data(c, OP_TEXT, msg, "compressed echo")
        # no_context_takeover: a second message must decompress standalone
        msg2 = ("second message, fresh context " * 20).encode()
        c.send(build_frame(OP_TEXT, pmd_compress(msg2), rsv1=True))
        expect_data(c, OP_TEXT, msg2, "second compressed echo")


def test_pmd_fragmented_unicode_with_ping(cfg):
    msg = ("联调客户端会把一条压缩消息切成多个帧，中间插入 Ping。" * 20).encode()
    comp = pmd_compress(msg)
    cut = len(comp) // 2
    with Conn(cfg, extensions="permessage-deflate") as c:
        c.send(build_frame(OP_TEXT, comp[:cut], fin=False, rsv1=True))
        c.send(build_frame(OP_PING, b"between"))
        c.send(build_frame(OP_CONT, comp[cut:], fin=True))
        f = c.read()
        check(f["opcode"] == OP_PONG and f["payload"] == b"between",
              f"expected pong between fragments, got {f}")
        expect_data(c, OP_TEXT, msg, "fragmented compressed echo")


def test_pmd_rsv1_on_continuation_rejected(cfg):
    comp = pmd_compress(b"some compressed text")
    cut = len(comp) // 2
    with Conn(cfg, extensions="permessage-deflate") as c:
        c.send(build_frame(OP_TEXT, comp[:cut], fin=False, rsv1=True))
        c.send(build_frame(OP_CONT, comp[cut:], fin=True, rsv1=True))
        expect_close(c, 1002)


def test_pmd_corrupt_stream(cfg):
    with Conn(cfg, extensions="permessage-deflate") as c:
        # 0xff as first byte: BFINAL=1 BTYPE=3 (reserved) -> instant zlib error
        c.send(build_frame(OP_TEXT, b"\xff\xffnot-deflate-at-all", rsv1=True))
        expect_close(c, 1002)


def test_pmd_corrupt_midmessage_no_partial_echo(cfg):
    comp = pmd_compress(b"valid prefix that must never be echoed" * 5)
    with Conn(cfg, extensions="permessage-deflate") as c:
        c.send(build_frame(OP_TEXT, comp, fin=False, rsv1=True))
        c.send(build_frame(OP_CONT, b"\xff\xffgarbage-tail", fin=True))
        expect_close(c, 1002)  # no decompressed prefix may be echoed first


def test_message_exactly_16k_ok(cfg):
    payload = b"a" * MAX_MESSAGE
    with Conn(cfg) as c:
        c.send(build_frame(OP_TEXT, payload))
        expect_data(c, OP_TEXT, payload, "16 KiB boundary echo")


def test_message_16k_plus_1_too_big(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_TEXT, b"a" * (MAX_MESSAGE + 1)))
        expect_close(c, 1009)


def test_fragmented_message_too_big(cfg):
    chunk = b"b" * 8192
    with Conn(cfg) as c:
        c.send(build_frame(OP_TEXT, chunk, fin=False))
        c.send(build_frame(OP_CONT, chunk, fin=False))
        c.send(build_frame(OP_CONT, b"b", fin=True))  # 16385 total
        expect_close(c, 1009)


def test_decompressed_too_big(cfg):
    big = b"A" * (100 * 1024)          # compresses to ~100 bytes
    comp = pmd_compress(big)
    check(len(comp) < 1024, "test premise: payload should compress well")
    with Conn(cfg, extensions="permessage-deflate") as c:
        c.send(build_frame(OP_TEXT, comp, rsv1=True))
        expect_close(c, 1009)


def test_close_echo_and_no_business_after_close(cfg):
    with Conn(cfg) as c:
        # close race: valid business message immediately after Close
        c.send(build_frame(OP_CLOSE, struct.pack("!H", 1000) + "bye".encode()),
               build_frame(OP_TEXT, b"must-not-be-echoed"))
        f = c.read()
        check(f["opcode"] == OP_CLOSE, f"expected close, got {f}")
        (code,) = struct.unpack("!H", f["payload"][:2])
        check(code == 1000, f"expected echoed code 1000, got {code}")
        # until TCP EOF the server must not emit any business frame
        c.settimeout(cfg.deadline + 3.0)
        try:
            while True:
                f = c.read()
                check(f["opcode"] not in (OP_TEXT, OP_BINARY),
                      f"business frame after close: {f['payload'][:40]!r}")
        except EOFError:
            pass


def test_close_deadline_enforced(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_TEXT, b"bad", masked=False))  # trigger 1002
        f = c.read()
        check(f["opcode"] == OP_CLOSE, f"expected close, got {f}")
        (code,) = struct.unpack("!H", f["payload"][:2])
        check(code == 1002, f"expected 1002, got {code}")
        # never answer with our own Close: server must give up at the deadline
        t0 = time.monotonic()
        c.settimeout(cfg.deadline + 5.0)
        try:
            while True:
                c.read()
        except EOFError:
            pass
        dt = time.monotonic() - t0
        check(dt < cfg.deadline + 2.0,
              f"TCP close took {dt:.2f}s, deadline is {cfg.deadline:.2f}s")
        check(dt > cfg.deadline * 0.5,
              f"TCP closed after {dt:.2f}s, suspiciously below deadline "
              f"{cfg.deadline:.2f}s (deadline not honoured?)")


def test_invalid_close_code_rejected(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_CLOSE, struct.pack("!H", 1006)))  # reserved
        expect_close(c, 1002)


def test_close_reason_not_utf8(cfg):
    with Conn(cfg) as c:
        c.send(build_frame(OP_CLOSE, struct.pack("!H", 1000) + b"\xff\xff"))
        expect_close(c, 1007)


def test_handshake_rejected_without_upgrade(cfg):
    sock = socket.create_connection((cfg.host, cfg.port), timeout=5)
    try:
        sock.sendall(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
        resp = sock.recv(4096)
        check(b" 400 " in resp.split(b"\r\n", 1)[0],
              f"expected 400, got {resp.split(chr(13).encode())[0]!r}")
    finally:
        sock.close()


TESTS = [
    ("basic text echo", test_basic_text),
    ("basic binary echo", test_basic_binary),
    ("multiple messages on one connection", test_multiple_messages_one_connection),
    ("ping -> pong", test_ping_pong),
    ("unsolicited pong ignored", test_pong_is_ignored),
    ("frame split byte-by-byte (split header)", test_split_header_byte_by_byte),
    ("ping between fragments", test_ping_between_fragments),
    ("utf-8 (Chinese) split across fragments", test_utf8_split_across_fragments),
    ("bad utf-8 -> 1007, no partial echo", test_bad_utf8_no_partial_echo),
    ("truncated utf-8 at message end -> 1007", test_truncated_utf8_at_message_end),
    ("unmasked frame -> 1002", test_unmasked_frame_rejected),
    ("RSV1 without negotiation -> 1002", test_rsv1_without_negotiation),
    ("fragmented control frame -> 1002", test_fragmented_control_rejected),
    ("oversize control frame -> 1002", test_oversize_control_rejected),
    ("orphan continuation -> 1002", test_unexpected_continuation_rejected),
    ("interleaved data frame -> 1002", test_interleaved_data_frame_rejected),
    ("reserved opcode -> 1002", test_reserved_opcode_rejected),
    ("pmd negotiation + compressed echo", test_pmd_negotiation_and_echo),
    ("pmd fragmented unicode with ping", test_pmd_fragmented_unicode_with_ping),
    ("pmd RSV1 on continuation -> 1002", test_pmd_rsv1_on_continuation_rejected),
    ("pmd corrupt stream -> 1002", test_pmd_corrupt_stream),
    ("pmd corrupt mid-message -> 1002, no partial echo",
     test_pmd_corrupt_midmessage_no_partial_echo),
    ("exactly 16 KiB echoed", test_message_exactly_16k_ok),
    ("16 KiB + 1 -> 1009", test_message_16k_plus_1_too_big),
    ("fragmented message over 16 KiB -> 1009", test_fragmented_message_too_big),
    ("decompressed over 16 KiB -> 1009", test_decompressed_too_big),
    ("close race: no business after close", test_close_echo_and_no_business_after_close),
    ("close deadline enforced", test_close_deadline_enforced),
    ("invalid close code -> 1002", test_invalid_close_code_rejected),
    ("close reason not utf-8 -> 1007", test_close_reason_not_utf8),
    ("handshake without upgrade -> 400", test_handshake_rejected_without_upgrade),
]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=18080)
    ap.add_argument("--close-deadline-ms", type=float, default=1500,
                    help="must match the server's WS_CLOSE_DEADLINE_MS")
    cfg = ap.parse_args()
    cfg.deadline = cfg.close_deadline_ms / 1000.0

    # wait for the server to accept connections (compose startup)
    deadline = time.monotonic() + 15
    while True:
        try:
            socket.create_connection((cfg.host, cfg.port), timeout=2).close()
            break
        except OSError:
            if time.monotonic() > deadline:
                print(f"server at {cfg.host}:{cfg.port} not reachable", file=sys.stderr)
                sys.exit(2)
            time.sleep(0.3)

    passed = failed = 0
    for name, fn in TESTS:
        try:
            fn(cfg)
            print(f"PASS  {name}")
            passed += 1
        except Exception as exc:
            print(f"FAIL  {name}: {exc}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed, {len(TESTS)} total")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
