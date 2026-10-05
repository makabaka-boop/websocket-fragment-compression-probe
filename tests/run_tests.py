#!/usr/bin/env python3
"""端到端联调：真实 TCP 连接 + 手工构帧，覆盖题目要求的全部异常与竞态。

运行方式（对 Docker Compose 暴露的 8080）：
    python3 tests/run_tests.py
也可直连本机进程：
    WS_HOST=127.0.0.1 WS_PORT=8080 python3 tests/run_tests.py

所有断言中，凡是“出错”的用例都会检查 frames_before_close 为空，
即服务端绝不可能先吐出半条回显再关闭。
"""
from __future__ import annotations

import os
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(__file__))

from ws_raw import (  # noqa: E402
    OP_BINARY,
    OP_CLOSE,
    OP_CONT,
    OP_PING,
    OP_PONG,
    OP_TEXT,
    RawSocketClosed,
    RawWS,
    connect,
    deflate_message,
    open_ws,
    reassemble,
)

HOST = os.environ.get("WS_HOST", "127.0.0.1")
PORT = int(os.environ.get("WS_PORT", "8080"))

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name}  {detail}")


def expect_close(client: RawWS, timeout: float = 6.0):
    return client.recv_until_close(timeout=timeout)


def section(title: str) -> None:
    print(f"\n=== {title} ===")


# ----------------------------------------------------------------------
# 1. 握手
# ----------------------------------------------------------------------
def t_handshake():
    section("HTTP 握手（成熟组件解析，规则按 RFC 6455）")
    c = connect(HOST, PORT)
    head = c.handshake(extra_headers={"Sec-WebSocket-Version": "12"})
    check("版本 12 被拒绝并回 Sec-WebSocket-Version: 13",
          b" 426 " in head and b"Sec-WebSocket-Version: 13" in head,
          head.decode("latin1", "replace"))
    c.close()

    c = connect(HOST, PORT)
    head = c.handshake(extra_headers={"Sec-WebSocket-Key": "not-base64!!!!"})
    check("非法 Sec-WebSocket-Key 返回 400", b" 400 " in head)
    c.close()

    c = connect(HOST, PORT)
    head = c.handshake(extra_headers={"Upgrade": "h2c", "Connection": "Upgrade"})
    check("缺少 Upgrade: websocket 返回 400", b" 400 " in head)
    c.close()

    c = connect(HOST, PORT)
    head = c.handshake(deflate=True)
    check("普通握手成功", b" 101 " in head and b"Sec-WebSocket-Accept:" in head)
    check(
        "只协商双向 no_context_takeover 的 permessage-deflate",
        b"Sec-WebSocket-Extensions: permessage-deflate;" in head
        and b"client_no_context_takeover" in head
        and b"server_no_context_takeover" in head,
        head.decode("latin1", "replace"),
    )
    c.close()

    c = connect(HOST, PORT)
    head = c.handshake(deflate=False)
    check("未声明扩展时 101 且不回 Extensions",
          b" 101 " in head and b"Sec-WebSocket-Extensions" not in head)
    c.close()


# ----------------------------------------------------------------------
# 2. 坏帧 -> 1002
# ----------------------------------------------------------------------
def t_bad_frames():
    section("坏帧 / 协议错误 -> Close 1002，且无半条回显")

    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, b"hi", masked=False)  # 未掩码
    code, _, before = expect_close(c)
    check("客户端帧未掩码 -> 1002", code == 1002, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, b"x", rsv1=True)  # 未协商压缩却置 RSV1
    code, _, before = expect_close(c)
    check("未协商 permessage-deflate 却带压缩位 -> 1002", code == 1002, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(OP_PING, b"p", fin=False)  # 控制帧分片
    code, _, before = expect_close(c)
    check("控制帧分片 -> 1002", code == 1002, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(OP_PING, b"x" * 126)  # 控制帧载荷 126
    code, _, before = expect_close(c)
    check("控制帧载荷超过 125 -> 1002", code == 1002, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(0x3, b"reserved")  # 保留 opcode
    code, _, before = expect_close(c)
    check("保留 opcode 0x3 -> 1002", code == 1002, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(OP_CONT, b"orphan")  # 无首帧的延续帧
    code, _, before = expect_close(c)
    check("没有首帧却发延续帧 -> 1002", code == 1002, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    c = open_ws(HOST, PORT, deflate=True)
    c.send_frame(OP_TEXT, b"abc", fin=False, rsv1=True)
    c.send_frame(OP_CONT, b"def", fin=True, rsv1=True)  # 延续帧带压缩位
    code, _, before = expect_close(c)
    check("压缩标记出现在延续帧 -> 1002", code == 1002, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, b"abc", fin=False)
    c.send_frame(OP_TEXT, b"def")  # 上一条还没收完
    code, _, before = expect_close(c)
    check("未 FIN 又开新消息 -> 1002", code == 1002, f"got {code}")
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(OP_CLOSE, b"\x03")  # 1 字节 Close
    code, _, before = expect_close(c)
    check("Close 帧只有 1 字节 -> 1002", code == 1002, f"got {code}")
    c.close()

    c = open_ws(HOST, PORT)
    c.send_close(1005)  # 禁止在线上出现的保留码
    code, _, _ = expect_close(c)
    check("Close 状态码 1005 -> 1002", code == 1002, f"got {code}")
    c.close()

    c = open_ws(HOST, PORT)
    c.send_close(1000, reason=b"\xff\xfe")  # 原因非 UTF-8
    code, _, _ = expect_close(c)
    check("Close 原因不是 UTF-8 -> 1007", code == 1007, f"got {code}")
    c.close()


# ----------------------------------------------------------------------
# 3. 坏文本 -> 1007
# ----------------------------------------------------------------------
def t_bad_text():
    section("坏文本 -> Close 1007（UTF-8 跨分片连续校验），无半条回显")

    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, b"\xff\xfe")
    code, _, before = expect_close(c)
    check("非法前导字节 -> 1007", code == 1007, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, "abc".encode() + b"\xed\xa0\x80")  # U+D800 代理
    code, _, before = expect_close(c)
    check("编码 UTF-16 代理 U+D800 -> 1007", code == 1007, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, b"\xc0\xaf")  # overlong '/'
    code, _, before = expect_close(c)
    check("过长编码 C0 AF -> 1007", code == 1007, f"got {code}")
    c.close()

    # 汉字字节被切开，第二片里给了错误的延续字节
    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, bytes([0xE4]), fin=False)   # “你”的首字节
    c.send_frame(OP_CONT, bytes([0x00, 0xA0]), fin=True)  # 延续字节 0x00 非法
    code, _, before = expect_close(c)
    check("跨片后延续字节非法 -> 1007", code == 1007, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    # FIN 时序列仍未闭合
    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, bytes([0xE4, 0xBD]), fin=False)
    c.send_frame(OP_CONT, b"", fin=True)  # 最终帧没有补齐第三字节
    code, _, before = expect_close(c)
    check("消息结束时 UTF-8 序列截断 -> 1007", code == 1007, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()


# ----------------------------------------------------------------------
# 4. 消息过大 -> 1009
# ----------------------------------------------------------------------
def t_size_limits():
    section("解压后超过 16 KiB -> Close 1009，无半条回显")

    c = open_ws(HOST, PORT)
    c.send_frame(OP_BINARY, b"A" * (16 * 1024 + 1))
    code, _, before = expect_close(c)
    check("未压缩 16385 字节 -> 1009", code == 1009, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(OP_BINARY, b"A" * (16 * 1024))
    fin, rsv1, op, payload = c.recv_frame()
    check("恰好 16384 字节正常回显",
          fin and op == OP_BINARY and len(payload) == 16 * 1024)
    c.send_close(1000)
    expect_close(c)
    c.close()

    # 跨分片累计超限：每片都合法，合起来超
    c = open_ws(HOST, PORT)
    c.send_frame(OP_BINARY, b"B" * 10000, fin=False)
    c.send_frame(OP_CONT, b"B" * 7000, fin=True)
    code, _, before = expect_close(c)
    check("分片合计 17000 字节 -> 1009", code == 1009, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()

    # 64 位长度声明远超单帧硬上限：只读头即可拒绝，不等载荷
    c = open_ws(HOST, PORT)
    hdr = RawWS.build_frame(OP_BINARY, b"")[:2]
    giant = bytes([hdr[0], 127 | 0x80]) + struct.pack("!Q", 2 * 1024 * 1024) + b"\x00\x00\x00\x00"
    c.sock.sendall(giant)
    code, _, before = expect_close(c)
    check("64 位长度声明 2 MiB -> 1009", code == 1009, f"got {code}")
    check("  └ 关闭前无任何回显", before == [])
    c.close()


# ----------------------------------------------------------------------
# 5. 压缩
# ----------------------------------------------------------------------
def t_deflate_errors():
    section("损坏压缩流 -> 1002；压缩炸弹（解压后超限）-> 1009")

    for name, garbage in (
        ("非法块类型 FE FF", b"\xfe\xff"),
        ("随机垃圾", b"\x9d\x7a\x3c\xab\xff"),
        ("翻转字节破坏 stored 块长度", bytes.fromhex("eac800040000")),
    ):
        c = open_ws(HOST, PORT, deflate=True)
        c.send_frame(OP_TEXT, garbage, rsv1=True)
        code, _, before = expect_close(c)
        check(f"{name} -> 1002", code == 1002, f"got {code}")
        check("  └ 关闭前无任何回显", before == [])
        c.close()

    # 压缩炸弹：20000 个 A 压完只有二十几字节
    c = open_ws(HOST, PORT, deflate=True)
    bomb = deflate_message(b"A" * 20000)
    check("炸弹在压缩后确实很小（压缩生效）", len(bomb) < 64, f"{len(bomb)} bytes")
    c.send_frame(OP_BINARY, bomb, rsv1=True)
    code, _, before = expect_close(c)
    check("解压后 20000 字节 -> 1009", code == 1009, f"got {code}")
    check("  └ 关闭前无任何回显（炸弹没被逐片吐出）", before == [])
    c.close()


def t_deflate_ok():
    section("permessage-deflate 正常路径（压缩标记仅首帧、尾部消息末补）")

    c = open_ws(HOST, PORT, deflate=True)
    msg = ("压缩回显测试 " * 200).encode()
    c.send_frame(OP_TEXT, deflate_message(msg), rsv1=True)
    fin, rsv1, op, payload = c.recv_frame()
    plain, was_compressed = reassemble([(fin, rsv1, op, payload)], True)
    check("长文本压缩往返一致", fin and op == OP_TEXT and plain == msg)
    check("服务端回显同样压缩（RSV1=1）", rsv1 and was_compressed)
    check("压缩确实缩小了体积", len(payload) < len(msg))
    c.send_close(1000)
    expect_close(c)
    c.close()

    c = open_ws(HOST, PORT, deflate=True)
    c.send_frame(OP_TEXT, deflate_message(b""), rsv1=True)
    fin, rsv1, op, payload = c.recv_frame()
    plain, _ = reassemble([(fin, rsv1, op, payload)], True)
    check("压缩的空消息往返", fin and op == OP_TEXT and plain == b"")
    c.send_close(1000)
    expect_close(c)
    c.close()

    # 压缩流按字节切成两片，中间插入 Ping：解压器跨片连续
    c = open_ws(HOST, PORT, deflate=True)
    msg = ("跨分片的压缩消息，" * 100 + "ABCDEFGH").encode()
    z = deflate_message(msg)
    cut = len(z) // 2
    c.send_frame(OP_TEXT, z[:cut], fin=False, rsv1=True)  # 压缩位只在首帧
    c.send_ping(b"mid")
    c.send_frame(OP_CONT, z[cut:], fin=True)             # 尾部由服务端补
    got = []
    while True:
        fin, rsv1, op, payload = c.recv_frame()
        if op == OP_PONG:
            check("分片间的 Ping 先收到 Pong", payload == b"mid")
            break
        got.append((fin, rsv1, op, payload))
    fin, rsv1, op, payload = c.recv_frame()
    got.append((fin, rsv1, op, payload))
    plain, _ = reassemble(got, True)
    check("压缩消息跨片 + 中间 Ping 后完整回显", plain == msg)
    check("只有一个完整回显帧", len(got) == 1 and got[0][0] and got[0][2] == OP_TEXT)
    c.send_close(1000)
    expect_close(c)
    c.close()


# ----------------------------------------------------------------------
# 6. 正常回显 / 分片 / Ping-Pong / 控制帧插在中间
# ----------------------------------------------------------------------
def t_normal_echo():
    section("正常回显：文本/二进制/延续帧/Ping/Pong")

    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, "hello".encode())
    fin, rsv1, op, payload = c.recv_frame()
    check("文本回显一致", fin and op == OP_TEXT and payload == b"hello")
    check("未协商时回显不压缩且无掩码", fin and not rsv1)
    c.send_close(1000)
    expect_close(c)
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(OP_BINARY, bytes(range(256)))
    fin, rsv1, op, payload = c.recv_frame()
    check("二进制 256 字节回显一致",
          fin and op == OP_BINARY and payload == bytes(range(256)))
    c.send_close(1000)
    expect_close(c)
    c.close()

    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, b"x" * 200)  # 触发 126 长度编码
    fin, _, op, payload = c.recv_frame()
    check("126 扩展长度（200 字节）", op == OP_TEXT and payload == b"x" * 200)
    c.send_close(1000)
    expect_close(c)
    c.close()

    # 非请求的 Pong 必须被忽略，消息仍正常回显
    c = open_ws(HOST, PORT)
    c.send_pong(b"unsolicited")
    c.send_frame(OP_BINARY, b"after-pong")
    fin, _, op, payload = c.recv_frame()
    check("主动 Pong 被忽略，后续消息照常回显", payload == b"after-pong")
    c.send_close(1000)
    expect_close(c)
    c.close()

    c = open_ws(HOST, PORT)
    c.send_ping(b"abc")
    fin, rsv1, op, payload = c.recv_frame()
    check("Ping 原样回 Pong（载荷一致）",
          op == OP_PONG and payload == b"abc" and fin)
    c.send_close(1000)
    expect_close(c)
    c.close()


def t_fragment_with_ping():
    section("分片消息中间插 Ping：控制帧绝不进解压器/消息缓冲，不提前交付")

    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, b"Hello, ", fin=False)
    c.send_ping(b"between")
    c.send_frame(OP_CONT, b"world!", fin=True)

    # 严格核对到达顺序：必须先 Pong，之后才出现完整文本
    fin, rsv1, op, payload = c.recv_frame()
    check("分片间先到 Pong", op == OP_PONG and payload == b"between",
          f"op={op}")
    fin, rsv1, op, payload = c.recv_frame()
    check(
        "文本在 FIN 后一次性完整交付（无半条）",
        fin and op == OP_TEXT and payload == b"Hello, world!",
        f"fin={fin} op={op} payload={payload!r}",
    )
    # 不应该再有任何数据帧
    c.send_close(1000)
    code, _, before = expect_close(c)
    check("完整交付后无多余半条数据帧", before == [])
    c.close()


def t_chinese_per_byte():
    section("汉字 UTF-8 逐字节跨帧（校验状态连续）")

    text = "你好，WebSocket！联调测试"
    raw = text.encode()
    c = open_ws(HOST, PORT)
    # 第一帧只带 1 个字节，其余每个字节一个延续帧，中间随机夹 Ping
    c.send_frame(OP_TEXT, raw[0:1], fin=False)
    parts = []
    idx = 1
    k = 0
    while idx < len(raw):
        c.send_frame(OP_CONT, raw[idx:idx + 1], fin=(idx == len(raw) - 1))
        idx += 1
        k += 1
        if k % 3 == 0:
            c.send_ping(str(k).encode())
    # 读完所有 Pong，再读唯一的回显
    data_frames = []
    pongs = 0
    c.sock.settimeout(6)
    for _ in range(20):
        fin, rsv1, op, payload = c.recv_frame()
        if op == OP_PONG:
            pongs += 1
        elif op in (OP_TEXT, OP_BINARY):
            data_frames.append((fin, rsv1, op, payload))
        if len(data_frames) == 1 and data_frames[0][0]:
            break
    plain, _ = reassemble(data_frames, False)
    check(f"逐字节分片（{len(raw)} 帧）+ {pongs} 个 Ping 后完整回显汉字",
          plain.decode() == text, plain[:40].decode("utf-8", "replace"))
    check("依然只有一个完整回显帧", len(data_frames) == 1)
    c.send_close(1000)
    expect_close(c)
    c.close()


# ----------------------------------------------------------------------
# 7. 关闭握手 / 竞态 / 关闭期限
# ----------------------------------------------------------------------
def t_close_race():
    section("Close 竞争：开始关闭后不再接收新业务消息，半成品不回显")

    # 分片消息中途先 Ping 再 Close：必须只见 Pong + Close，无文本
    c = open_ws(HOST, PORT)
    c.send_frame(OP_TEXT, b"partial", fin=False)
    c.send_ping(b"race")
    c.send_close(1000, b"bye")
    first = c.recv_frame()
    check("竞争中先回 Pong", first[2] == OP_PONG and first[3] == b"race")
    second = c.recv_frame()
    check("随后回 Close 1000/bye",
          second[2] == OP_CLOSE and second[3] == b"\x03\xe8bye")
    code, _, before = expect_close(c)
    check("半成品文本绝无回显", before == [])
    c.close()

    # Close 之后继续塞业务帧：必须被忽略，不能回显也不能重置关闭
    c = open_ws(HOST, PORT)
    c.send_close(1000)
    time.sleep(0.1)
    c.send_frame(OP_TEXT, b"too late")
    c.send_ping(b"late-ping")
    code, _, before = expect_close(c, timeout=6)
    check("Close 后业务帧被忽略（回显列表为空）", before == [])
    c.close()

    # 正常有序关闭：状态码被原样回显
    c = open_ws(HOST, PORT)
    c.send_close(1000)
    code, _, _ = expect_close(c)
    check("有序关闭回显 1000", code == 1000, f"got {code}")
    c.close()


def t_close_deadline():
    section("关闭期限可注入：对端不回 Close 时，期限后 TCP 被断开")

    c = open_ws(HOST, PORT)
    t0 = time.monotonic()
    c.send_close(1000)
    code, _, _ = expect_close(c)
    check("先收到服务端 Close", code == 1000)
    # 故意不回 Close、不关 socket，干等 TCP RST/FIN
    try:
        c.sock.settimeout(8)
        while True:
            chunk = c.sock.recv(4096)
            if not chunk:
                break
        elapsed = time.monotonic() - t0
        check(f"期限后服务端断开 TCP（实测 {elapsed:.1f}s）", elapsed < 6)
    except (socket.timeout, RawSocketClosed):
        check("期限后服务端断开 TCP", True)
    c.close()


# ----------------------------------------------------------------------
# 8. TCP 层手工拆头
# ----------------------------------------------------------------------
def t_tcp_splitting():
    section("真实 TCP 手工拆头：帧头/掩码/载荷分包发送")

    c = open_ws(HOST, PORT)
    frame = RawWS.build_frame(OP_TEXT, "拆头发送".encode())
    # 第 1 字节、其余头、掩码、载荷全部拆开，中间 sleep 模拟 Nagle/延迟
    pieces = [frame[0:1], frame[1:2], frame[2:6], frame[6:]]
    for i, p in enumerate(pieces):
        c.sock.sendall(p)
        time.sleep(0.15)
    fin, rsv1, op, payload = c.recv_frame()
    check("帧头跨 TCP 段仍正确组装", payload == "拆头发送".encode(),
          payload.decode("utf-8", "replace"))
    c.send_close(1000)
    expect_close(c)
    c.close()

    # 握手请求与首个 WebSocket 帧在同一个 TCP 包里（管线化，不得丢字节）
    import base64

    s = socket.create_connection((HOST, PORT), timeout=6)
    c = RawWS(s)
    key = base64.b64encode(b"0123456789abcdef").decode()
    req = (
        b"GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        + b"Sec-WebSocket-Key: " + key.encode() + b"\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    c.sock.sendall(req + RawWS.build_frame(OP_TEXT, b"pipelined"))
    resp = b""
    while b"\r\n\r\n" not in resp:
        resp += c.sock.recv(4096)
    head, _, leftover = resp.partition(b"\r\n\r\n")
    c.buf += leftover
    check("管线化握手成功", b" 101 " in head)
    fin, rsv1, op, payload = c.recv_frame()
    check("管线化的首帧被正确读取并回显", payload == b"pipelined", repr(payload))
    c.send_close(1000)
    expect_close(c)
    c.close()


def main() -> int:
    tests = [
        t_handshake,
        t_bad_frames,
        t_bad_text,
        t_size_limits,
        t_deflate_errors,
        t_deflate_ok,
        t_normal_echo,
        t_fragment_with_ping,
        t_chinese_per_byte,
        t_close_race,
        t_close_deadline,
        t_tcp_splitting,
    ]
    for t in tests:
        try:
            t()
        except (RawSocketClosed, ConnectionError, OSError, AssertionError) as exc:
            global FAIL
            FAIL += 1
            print(f"  ERROR {t.__name__}: {type(exc).__name__}: {exc}")

    print(f"\n================ 结果: {PASS} 通过, {FAIL} 失败 ================")
    return 1 if FAIL else 0


if __name__ == "__main__":
    sys.exit(main())
