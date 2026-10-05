"""RFC 6455 §7.4.1 关闭码与本地异常分类。

三类致命错误对应不同关闭码：
  * 协议错误 -> 1002（坏帧：掩码缺失、非法 opcode、控制帧分片、RSV 位非法等）
  * 文本错误 -> 1007（消息体或 Close 原因不是合法 UTF-8）
  * 消息过大 -> 1009（解压后完整消息超过 16 KiB）
压缩流损坏没有单独的状态码，按“协议错误”处理（1002）。
"""
from __future__ import annotations


class WebSocketError(Exception):
    """所有需要以 Close 帧结束的本地错误基类。"""

    code: int = 1002
    reason: str = "protocol error"

    def __init__(self, reason: str | None = None, code: int | None = None):
        if reason is not None:
            self.reason = reason
        if code is not None:
            self.code = code
        super().__init__(f"{self.code} {self.reason}")


class ProtocolError(WebSocketError):
    """坏帧 / 压缩流损坏等协议违规，关闭码 1002。"""

    code = 1002
    reason = "protocol error"


class TextDecodeError(WebSocketError):
    """完整消息或 Close 原因不是合法 UTF-8，关闭码 1007。"""

    code = 1007
    reason = "invalid utf-8 payload"


class MessageTooLarge(WebSocketError):
    """解压后消息超过协商上限（16 KiB），关闭码 1009。"""

    code = 1009
    reason = "message too big"
