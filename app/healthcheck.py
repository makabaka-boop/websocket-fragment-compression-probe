#!/usr/bin/env python3
"""容器健康检查：直接 TCP 连接并完成 WebSocket 握手（stdlib，无第三方）。

只验证“有进程在监听且能完成升级”，不做消息往返，避免给业务造成负担。
"""
from __future__ import annotations

import base64
import os
import socket
import sys

HOST = os.environ.get("WS_HOST", "127.0.0.1")
PORT = int(os.environ.get("WS_PORT", "8080"))

req = (
    b"GET / HTTP/1.1\r\n"
    b"Host: localhost\r\n"
    b"Upgrade: websocket\r\n"
    b"Connection: Upgrade\r\n"
    b"Sec-WebSocket-Key: " + base64.b64encode(b"healthcheck-1234") + b"\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"\r\n"
)

try:
    with socket.create_connection((HOST, PORT), timeout=3) as s:
        s.sendall(req)
        data = s.recv(4096)
except OSError as exc:
    print(f"healthcheck failed: {exc}", file=sys.stderr)
    sys.exit(1)

if b"101 Switching Protocols" in data and b"Sec-WebSocket-Accept:" in data:
    sys.exit(0)
print("healthcheck failed: no 101 response", file=sys.stderr)
sys.exit(1)
