# 本地 RFC 6455 回显服务（手工帧/消息状态机）

一个仅依赖 Python 3.11 标准库的 WebSocket 回显服务。HTTP 握手复用标准库
成熟组件（`http.client.parse_headers`），**RFC 6455 的帧解析、消息装配、
分片、控制帧、关闭握手与 permessage-deflate 状态全部自行实现**，没有调用
任何现成的 WebSocket 收发引擎。

## 运行（Docker Compose，容器内唯一监听进程）

```bash
docker compose up --build
# 监听 0.0.0.0:8080；默认关闭期限 5 秒，可注入：
WS_CLOSE_TIMEOUT=1 docker compose up --build
```

compose 里只有 `echo-ws` 一个服务，`CMD` 即唯一监听进程
（`python -m app.server`，`init: true`，无 shell/supervisor）。

环境变量：

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `WS_HOST` | `0.0.0.0` | 监听地址 |
| `WS_PORT` | `8080` | 监听端口 |
| `WS_CLOSE_TIMEOUT` | `5` | 关闭期限（秒，浮点），发完 Close 后等对端 Close/FIN 的最长时间，可注入 |

## 联调测试（真实 TCP + 手工拼字节，不用任何 WebSocket 库）

```bash
python3 tests/run_tests.py                 # 对 127.0.0.1:8080
WS_PORT=8080 python3 tests/run_tests.py
```

测试客户端（`tests/ws_raw.py`）逐字节构造帧头/掩码/扩展长度，覆盖：
拆头发送、分片之间插 Ping、汉字逐字节跨帧、损坏压缩流、压缩炸弹、
关闭竞争（分片消息中途 Close、Close 后再塞业务帧）、关闭期限断开，
并逐条核对出错前**没有任何半条回显**。

## 代码结构与需求映射

| 文件 | 职责 |
| --- | --- |
| `app/framing.py` | RFC 6455 §5.2 帧编解码：16/64 位长度、**客户端必须掩码**、服务端不掩码、最短长度编码、控制帧 ≤125 且不得分片、保留 opcode |
| `app/utf8.py` | 流式 UTF-8（RFC 3629）校验器，**状态跨分片连续**，拒绝过长编码/代理/超 U+10FFFF，FIN 才判定截断 |
| `app/extension.py` | permessage-deflate（RFC 7692）：只协商双向 `*_no_context_takeover`；raw DEFLATE（zlib 只承担 DEFLATE 算法）；**RSV1 只属于首帧**，`00 00 ff ff` 尾部只在 FIN 补；每消息独立解压器；损坏流→1002，解压后超限→1009 |
| `app/handshake.py` | §4.2 握手（标准库解析 HTTP 头），校验 Upgrade/Connection/Key/Version，按压缩协商回 101/Extensions |
| `app/connection.py` | 帧/消息状态机：控制帧绝不进消息缓冲或解压器；消息 FIN + 解压完整 + UTF-8 通过 + ≤16 KiB 才一次性回显；Close 后丢弃半成品、不再接受业务消息；关闭期限等待 |
| `app/server.py` | 唯一监听进程入口、信号优雅退出 |
| `app/healthcheck.py` | 容器健康检查（裸 TCP 完成升级握手） |

## 关闭码约定

| 情况 | 码 |
| --- | --- |
| 坏帧（无掩码、非法 opcode/RSV、控制帧分片或超长、压缩位违规等）、**损坏的 DEFLATE 流** | `1002` 协议错误 |
| 文本消息或 Close 原因非合法 UTF-8 | `1007` 文本错误 |
| **解压后**完整消息超过 16 KiB（含压缩炸弹） | `1009` 消息过大 |

回显规则：文本/二进制（含压缩与分片）只有在全部校验通过后才回显完整消息；
服务端压缩回显时同样只在首帧打 RSV1；Ping 原样回 Pong（允许夹在分片之间）；
主动 Pong 忽略；收到 Close 后回 Close 并在关闭期限内等待对端关闭。
