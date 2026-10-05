# ws-echo — 手写帧引擎的 RFC 6455 回显服务

针对"压缩消息被切成多帧、中间插入 Ping"的联调场景：接收路径完全自行实现
RFC 6455 帧编解码与消息状态机，控制帧永远不会进入解压器，半条消息永远不会
被提前交付。仅 HTTP Upgrade 握手复用成熟组件（Python `http.server`），
未使用任何现成的 WebSocket 收发引擎。

## 运行

```bash
# 唯一监听进程（容器内 8080，宿主映射 127.0.0.1:18080）
docker compose up --build

# 手工构造帧的原始 TCP 测试（31 项），从宿主机执行：
python3 test_ws_echo.py --port 18080 --close-deadline-ms 1500

# 或在 compose 内执行（一次性客户端，不是监听进程）：
docker compose --profile test run --rm ws-echo-tests
```

无 Docker 时也可直接本地运行：`WS_PORT=18080 python3 ws_echo_server.py`。

## 配置（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `WS_PORT` | `8080` | 监听端口 |
| `WS_CLOSE_DEADLINE_MS` | `3000` | 可注入的关闭期限：发出 Close 后等待对端 Close 的上限，到期强制关闭 TCP |

## 协议行为

- **帧**：客户端帧必须带掩码；支持 text/binary/continuation/ping/pong/close；
  保留操作码、RSV2/RSV3、64 位长度最高位置位均为协议错误。
- **分片**：continuation 必须属于已打开的消息；消息未结束不得开启新数据帧；
  控制帧不得分片且载荷 ≤ 125；Ping 可出现在分片之间，不影响消息状态，
  立即回复 Pong。
- **permessage-deflate**：仅协商双向 `no_context_takeover`
  （`permessage-deflate; server_no_context_takeover; client_no_context_takeover`）。
  未协商时 RSV1 直接拒绝；协商后 RSV1 只允许出现在消息首个数据帧。
  DEFLATE 由 zlib 承担（raw，`wbits=-15`），`0x00 0x00 0xff 0xff` 尾部只在
  消息结束帧到达时补入。
- **UTF-8**：文本消息使用增量解码器跨分片连续校验，多字节字符可跨帧拆分；
  消息结束时字符边界不完整也算文本错误。
- **大小**：完整消息（解压后）上限 16 KiB；单帧线上 sanity 上限 64 KiB。
- **回显**：仅在全部校验通过、消息完整后才回显（单帧，原操作码，不压缩）。
- **关闭**：坏帧 → 1002，坏文本（含 Close reason 非 UTF-8）→ 1007，
  超限 → 1009。Close 握手一旦开始（任一方向），不再接收新业务消息；
  等待对端 Close 以 `WS_CLOSE_DEADLINE_MS` 为限，期间遇到的垃圾字节不会
  缩短期限。

## 测试覆盖（test_ws_echo.py，全部手工构造帧）

拆头（逐字节发送）、分片间 Ping、汉字跨帧（多字节字符被切开）、损坏压缩流
（首帧即坏 / 消息中途坏）、解压后超限、16 KiB 边界 ±1、未掩码、未协商 RSV1、
分片控制帧、孤儿 continuation、帧交错、保留操作码、关闭竞争（Close 后紧跟
业务消息不得回显）、关闭期限强制生效、非法关闭码等。凡校验失败的用例都断言
**关闭帧之前没有任何业务帧**（无半条回显）。
