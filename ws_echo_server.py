#!/usr/bin/env python3
"""RFC 6455 WebSocket echo server with a hand-written frame engine.

What is implemented by hand on top of the raw socket (no WebSocket library):
  - frame codec: FIN/RSV/opcode parsing, extended lengths, client masking
  - message state machine: text/binary/continuation reassembly
  - control frames: ping/pong/close, never fragmented, never fed to the
    decompressor, never interleaved into message state
  - permessage-deflate (RFC 7691) negotiated ONLY with both
    server_no_context_takeover and client_no_context_takeover; RSV1 accepted
    only when negotiated and only on the first data frame of a message
  - raw-DEFLATE via zlib; the 0x00 0x00 0xff 0xff tail is appended only when
    the message-final frame arrives
  - incremental UTF-8 validation that stays continuous across fragments
  - 16 KiB cap on the complete (decompressed) message
  - failure closes: 1002 protocol error, 1007 bad text, 1009 message too big
  - close handshake with an injectable deadline (WS_CLOSE_DEADLINE_MS); once
    a close has started, further business messages are ignored

The HTTP Upgrade handshake reuses a mature component (http.server).
"""

from __future__ import annotations

import base64
import codecs
import hashlib
import logging
import os
import socket
import struct
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("ws-echo")

MAX_MESSAGE_BYTES = 16 * 1024      # cap on the complete (decompressed) message
MAX_FRAME_BYTES = 64 * 1024        # sanity cap for a single frame on the wire
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
DEFLATE_TAIL = b"\x00\x00\xff\xff"  # appended at message end per RFC 7691

OP_CONT, OP_TEXT, OP_BINARY = 0x0, 0x1, 0x2
OP_CLOSE, OP_PING, OP_PONG = 0x8, 0x9, 0xA
DATA_OPCODES = (OP_CONT, OP_TEXT, OP_BINARY)
CONTROL_OPCODES = (OP_CLOSE, OP_PING, OP_PONG)

CLOSE_NORMAL = 1000
CLOSE_PROTOCOL_ERROR = 1002
CLOSE_BAD_TEXT = 1007
CLOSE_TOO_BIG = 1009

_VALID_CLOSE_CODES = frozenset({1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011})


def _valid_close_code(code: int) -> bool:
    return code in _VALID_CLOSE_CODES or 3000 <= code <= 4999


class PeerGone(Exception):
    """TCP EOF or reset while reading."""


class ProtocolError(Exception):
    """RFC 6455/7691 violation -> close 1002."""


class BadText(Exception):
    """Invalid UTF-8 in a text message -> close 1007."""


class TooBig(Exception):
    """Message exceeds the 16 KiB cap -> close 1009."""


class WebSocketConnection:
    """One upgraded connection: hand-written frame loop and message state."""

    def __init__(self, conn: socket.socket, rfile, pmd_enabled: bool, close_deadline: float):
        self.conn = conn
        self.rfile = rfile
        self.pmd_enabled = pmd_enabled
        self.close_deadline = close_deadline

        # fragmented-message state (reset when a message completes)
        self.msg_opcode: int | None = None   # opcode of the open message, None if idle
        self.msg_compressed = False
        self.msg_buf = bytearray()
        self.decompressor: zlib.Decompress | None = None
        self.utf8_decoder = None             # incremental decoder for text messages

        self.close_sent = False
        self.close_received = False

    # ------------------------------------------------------------------ I/O

    def _read_exact(self, n: int) -> bytes:
        data = self.rfile.read(n)
        if data is None or len(data) < n:
            raise PeerGone()
        return data

    def read_frame(self):
        """Read and structurally validate one frame. Returns (fin, rsv1, opcode, payload)."""
        b1, b2 = self._read_exact(2)
        fin = bool(b1 & 0x80)
        rsv1 = bool(b1 & 0x40)
        if b1 & 0x30:
            raise ProtocolError("RSV2/RSV3 set")
        opcode = b1 & 0x0F
        if opcode not in DATA_OPCODES + CONTROL_OPCODES:
            raise ProtocolError(f"reserved opcode {opcode:#x}")
        if not (b2 & 0x80):
            raise ProtocolError("client frame is not masked")
        length = b2 & 0x7F
        if length == 126:
            (length,) = struct.unpack("!H", self._read_exact(2))
        elif length == 127:
            (length,) = struct.unpack("!Q", self._read_exact(8))
            if length >= 1 << 63:
                raise ProtocolError("invalid 64-bit payload length")
        if opcode in CONTROL_OPCODES:
            if not fin:
                raise ProtocolError("control frame must not be fragmented")
            if length > 125:
                raise ProtocolError("control frame payload exceeds 125 bytes")
            if rsv1:
                raise ProtocolError("RSV1 set on control frame")
        if length > MAX_FRAME_BYTES:
            raise TooBig("single frame exceeds sanity cap")
        mask_key = self._read_exact(4)
        payload = bytearray(self._read_exact(length)) if length else bytearray()
        for i in range(length):
            payload[i] ^= mask_key[i & 3]
        return fin, rsv1, opcode, bytes(payload)

    def send_frame(self, opcode: int, payload: bytes = b"", fin: bool = True):
        b1 = (0x80 if fin else 0) | opcode
        n = len(payload)
        if n < 126:
            header = struct.pack("!BB", b1, n)
        elif n <= 0xFFFF:
            header = struct.pack("!BBH", b1, 126, n)
        else:
            header = struct.pack("!BBQ", b1, 127, n)
        self.conn.sendall(header + payload)

    def send_close(self, code: int, reason: bytes = b""):
        if self.close_sent:
            return
        self.close_sent = True
        try:
            self.send_frame(OP_CLOSE, struct.pack("!H", code) + reason[:123])
        except OSError:
            pass

    # ------------------------------------------------------------- messages

    def handle_frame(self, fin: bool, rsv1: bool, opcode: int, payload: bytes):
        if opcode in CONTROL_OPCODES:
            self._handle_control(opcode, payload)
            return
        if self.close_sent or self.close_received:
            return  # close already started: business messages are no longer accepted
        if opcode == OP_CONT:
            if rsv1:
                raise ProtocolError("RSV1 set on continuation frame")
            if self.msg_opcode is None:
                raise ProtocolError("continuation frame without an open message")
        else:
            if self.msg_opcode is not None:
                raise ProtocolError("new data frame while a fragmented message is open")
            if rsv1 and not self.pmd_enabled:
                raise ProtocolError("RSV1 set but permessage-deflate was not negotiated")
            self.msg_opcode = opcode
            self.msg_compressed = rsv1
            self.msg_buf = bytearray()
            self.decompressor = zlib.decompressobj(-15) if rsv1 else None
            self.utf8_decoder = (
                codecs.getincrementaldecoder("utf-8")(errors="strict")
                if opcode == OP_TEXT else None
            )
        self._feed_message(payload, fin)

    def _feed_message(self, payload: bytes, fin: bool):
        data = payload
        if self.decompressor is not None:
            try:
                data = self.decompressor.decompress(payload)
                if fin:
                    # message end: append the DEFLATE tail only now
                    data += self.decompressor.decompress(DEFLATE_TAIL)
                    data += self.decompressor.flush()
            except zlib.error as exc:
                raise ProtocolError(f"corrupt deflate stream: {exc}") from exc
        if len(self.msg_buf) + len(data) > MAX_MESSAGE_BYTES:
            raise TooBig("message exceeds 16 KiB")
        self.msg_buf += data
        if self.utf8_decoder is not None:
            try:
                # incremental: multi-byte sequences may span fragments
                self.utf8_decoder.decode(data, final=fin)
            except UnicodeDecodeError as exc:
                raise BadText(f"invalid UTF-8: {exc}") from exc
        if not fin:
            return
        message = bytes(self.msg_buf)
        opcode = self.msg_opcode
        self.msg_opcode = None
        self.msg_compressed = False
        self.msg_buf = bytearray()
        self.decompressor = None
        self.utf8_decoder = None
        # echo only now: every check for the complete message has passed
        self.send_frame(opcode, message)

    def _handle_control(self, opcode: int, payload: bytes):
        if opcode == OP_PING:
            if not (self.close_sent or self.close_received):
                self.send_frame(OP_PONG, payload)
        elif opcode == OP_PONG:
            pass
        elif opcode == OP_CLOSE:
            if self.close_received:
                return
            self.close_received = True
            code = None
            if len(payload) == 1:
                raise ProtocolError("close frame with 1-byte payload")
            if len(payload) >= 2:
                (code,) = struct.unpack("!H", payload[:2])
                if not _valid_close_code(code):
                    raise ProtocolError(f"invalid close code {code}")
                try:
                    payload[2:].decode("utf-8", errors="strict")
                except UnicodeDecodeError as exc:
                    raise BadText(f"close reason is not UTF-8: {exc}") from exc
            if not self.close_sent:
                self.send_close(code if code is not None else CLOSE_NORMAL)

    # ----------------------------------------------------------------- loop

    def run(self):
        try:
            while not (self.close_sent and self.close_received):
                fin, rsv1, opcode, payload = self.read_frame()
                self.handle_frame(fin, rsv1, opcode, payload)
            # clean close handshake done; give the peer a moment to close TCP
            self._drain(min(self.close_deadline, 1.0), watch_close=False)
        except PeerGone:
            pass
        except TooBig as exc:
            self._fail(CLOSE_TOO_BIG, str(exc))
        except BadText as exc:
            self._fail(CLOSE_BAD_TEXT, str(exc))
        except ProtocolError as exc:
            self._fail(CLOSE_PROTOCOL_ERROR, str(exc))
        except OSError:
            pass
        finally:
            try:
                self.conn.close()
            except OSError:
                pass

    def _fail(self, code: int, reason: str):
        log.info("closing with %d: %s", code, reason)
        self.send_close(code, reason.encode("utf-8", "replace"))
        # wait for the peer's Close, bounded by the injectable deadline
        self._drain(self.close_deadline, watch_close=True)

    def _drain(self, timeout: float, watch_close: bool):
        """Read and discard frames until the peer's Close (optional), EOF, or
        the deadline. Unparseable bytes while closing must not cut the wait
        short: fall back to raw discarding."""
        try:
            self.conn.settimeout(timeout)
        except OSError:
            return
        while True:
            try:
                _, _, opcode, _ = self.read_frame()
            except (PeerGone, OSError):
                return  # EOF, reset, or deadline elapsed (timeout)
            except Exception:
                self._raw_discard()
                return
            if watch_close and opcode == OP_CLOSE:
                self.close_received = True
                return

    def _raw_discard(self):
        while True:
            try:
                if not self.conn.recv(4096):
                    return
            except OSError:  # includes socket.timeout (deadline elapsed)
                return


# ------------------------------------------------------------- HTTP upgrade


class WebSocketHandshakeHandler(BaseHTTPRequestHandler):
    """HTTP Upgrade handshake (the only part delegated to a mature component)."""

    protocol_version = "HTTP/1.1"
    server_version = "WSEcho/1.0"

    def do_GET(self):
        if self.headers.get("Upgrade", "").lower() != "websocket":
            return self._reject(400, "missing or invalid Upgrade header")
        tokens = [t.strip().lower() for t in self.headers.get("Connection", "").split(",")]
        if "upgrade" not in tokens:
            return self._reject(400, "missing Connection: upgrade")
        key = self.headers.get("Sec-WebSocket-Key")
        if not key:
            return self._reject(400, "missing Sec-WebSocket-Key")
        if self.headers.get("Sec-WebSocket-Version") != "13":
            return self._reject(426, "unsupported WebSocket version",
                                [("Sec-WebSocket-Version", "13")])

        pmd = False
        for offer in self.headers.get("Sec-WebSocket-Extensions", "").split(","):
            if offer.split(";")[0].strip().lower() == "permessage-deflate":
                pmd = True

        accept = base64.b64encode(
            hashlib.sha1((key + WS_GUID).encode("ascii")).digest()
        ).decode("ascii")
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        if pmd:
            # the only flavour we negotiate: no context takeover in either direction
            self.send_header("Sec-WebSocket-Extensions",
                             "permessage-deflate; server_no_context_takeover; "
                             "client_no_context_takeover")
        self.end_headers()
        self.close_connection = True

        peer = self.client_address
        log.info("%s:%d upgraded (permessage-deflate=%s)", peer[0], peer[1], pmd)
        try:
            WebSocketConnection(
                self.connection, self.rfile, pmd, self.server.close_deadline
            ).run()
        except Exception:
            log.exception("unexpected error in connection loop")
        log.info("%s:%d disconnected", peer[0], peer[1])

    def _reject(self, status: int, message: str, extra_headers=()):
        body = (message + "\n").encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        for k, v in extra_headers:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def log_message(self, fmt, *args):
        log.info("http: " + fmt, *args)


class WebSocketServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    port = int(os.environ.get("WS_PORT", "8080"))
    deadline_ms = float(os.environ.get("WS_CLOSE_DEADLINE_MS", "3000"))
    server = WebSocketServer(("0.0.0.0", port), WebSocketHandshakeHandler)
    server.close_deadline = deadline_ms / 1000.0
    log.info("listening on 0.0.0.0:%d (close deadline %.0f ms, max message %d bytes)",
             port, deadline_ms, MAX_MESSAGE_BYTES)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
