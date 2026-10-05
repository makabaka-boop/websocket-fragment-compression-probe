"""流式 UTF-8 校验器（RFC 3629），状态在分片之间保持连续。

WebSocket 的文本消息可能横跨多个数据帧，UTF-8 校验必须在“整条消息”
层面进行：一个汉字的三个字节可以落在两个不同的帧里。校验器保存尚未
闭合的序列头（最多 3 字节），下次 feed 时拼接后继续判定。消息结束时
调用 finish()，仍有未闭合序列即文本错误（1007）。

非法形式全部拒绝：孤立的延续字节、过长编码（overlong）、UTF-16 代理
（U+D800..U+DFFF）以及超过 U+10FFFF 的码位。
"""
from __future__ import annotations

from .errors import TextDecodeError


class IncrementalUTF8Validator:
    def __init__(self) -> None:
        # 上一片末尾可能开始的未闭合多字节序列，长度 0..3
        self._pending = b""

    def feed(self, data: bytes) -> None:
        self._pending = self._consume(self._pending + bytes(data), final=False)

    def finish(self) -> None:
        # 消息结束时若仍有未闭合序列，属于截断的非法文本
        self._consume(self._pending, final=True)
        self._pending = b""

    def reset(self) -> None:
        self._pending = b""

    @staticmethod
    def _consume(data: bytes, final: bool) -> bytes:
        """校验 data 中所有完整序列，返回未闭合的尾部；非法即抛 1007。"""
        i = 0
        n = len(data)
        while i < n:
            b = data[i]
            if b < 0x80:
                i += 1
                continue
            if b < 0xC2:
                # 0x80-0xBF：孤立的延续字节；0xC0-0xC1：只可能产生过长编码
                raise TextDecodeError("invalid utf-8 lead byte")
            if b <= 0xDF:
                total = 2
            elif b <= 0xEF:
                total = 3
            elif b <= 0xF4:
                total = 4
            else:
                # 0xF5-0xFF：超出 UTF-8 编码范围
                raise TextDecodeError("invalid utf-8 lead byte")

            available = n - i - 1
            if available < total - 1:
                # 序列跨片：手头的延续字节先做基本范围检查
                for k in range(i + 1, n):
                    if not (0x80 <= data[k] <= 0xBF):
                        raise TextDecodeError("invalid utf-8 continuation byte")
                if final:
                    raise TextDecodeError("truncated utf-8 sequence at message end")
                return bytes(data[i:])  # 留给下一片，最多 3 字节

            seq = data[i + 1:i + total]
            if any(not (0x80 <= c <= 0xBF) for c in seq):
                raise TextDecodeError("invalid utf-8 continuation byte")

            if total == 2:
                code = ((b & 0x1F) << 6) | (seq[0] & 0x3F)
                if code < 0x80:
                    raise TextDecodeError("overlong utf-8 sequence")
            elif total == 3:
                code = ((b & 0x0F) << 12) | ((seq[0] & 0x3F) << 6) | (seq[1] & 0x3F)
                if code < 0x800:
                    raise TextDecodeError("overlong utf-8 sequence")
                if 0xD800 <= code <= 0xDFFF:
                    raise TextDecodeError("utf-8 encodes utf-16 surrogate")
            else:
                code = (
                    ((b & 0x07) << 18)
                    | ((seq[0] & 0x3F) << 12)
                    | ((seq[1] & 0x3F) << 6)
                    | (seq[2] & 0x3F)
                )
                if code < 0x10000:
                    raise TextDecodeError("overlong utf-8 sequence")
                if code > 0x10FFFF:
                    raise TextDecodeError("code point above U+10FFFF")
            i += total
        return b""
