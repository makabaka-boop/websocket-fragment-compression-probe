"""本地回显服务入口：唯一监听进程。

监听 ``WS_HOST:WS_PORT``（默认 0.0.0.0:8080），关闭期限可由
``WS_CLOSE_TIMEOUT``（秒，浮点）注入，供测试压缩关闭竞争。
不使用任何现成 WebSocket 收发引擎——HTTP 头解析复用标准库，
RFC 6455 帧与消息状态全部自行实现。
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
import os
import signal

from .connection import handle_client

LOG = logging.getLogger("echo-ws")

# StreamReader 缓冲上限：略大于单帧 1 MiB 硬上限
STREAM_LIMIT = 2 * 1024 * 1024


async def serve(host: str, port: int, close_timeout: float) -> None:
    server = await asyncio.start_server(
        lambda r, w: handle_client(r, w, close_timeout),
        host,
        port,
        limit=STREAM_LIMIT,
    )
    LOG.info("listening on %s:%s (close_timeout=%ss)", host, port, close_timeout)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        with contextlib.suppress(NotImplementedError):
            loop.add_signal_handler(sig, stop.set)

    try:
        await stop.wait()
    finally:
        LOG.info("shutting down")
        server.close()
        await server.wait_closed()
        # 让在途连接把 Close 发出去
        await asyncio.sleep(0)


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("WS_LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    host = os.environ.get("WS_HOST", "0.0.0.0")
    port = int(os.environ.get("WS_PORT", "8080"))
    close_timeout = float(os.environ.get("WS_CLOSE_TIMEOUT", "5"))
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(serve(host, port, close_timeout))


if __name__ == "__main__":
    main()
