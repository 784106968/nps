# 架构说明

## 分层

```text
GUI (P1+)                 PySide6：三窗格、会话视图、流时序图
   │  只读模型 / 只发命令
会话与识别层 (P3+)        五元组规范化、会话表、DPI、显示过滤求值
   │
核心层                    Packet 模型、有界队列、统计
   │
捕获层                    ctypes → libpcap/Npcap 新 API
```

调用方向严格单向：上层依赖下层，下层不认识上层。捕获层不得 import GUI 或 Qt。

## 线程模型

| 线程 | 职责 | 约束 |
| --- | --- | --- |
| 捕获线程 | `pcap_dispatch` 循环 | 回调内只做 `string_at` 拷贝与入队，禁止解析/日志/IO |
| 解析线程（P3+） | 分层解析、会话聚合、DPI | 从队列批量取包 |
| GUI 主线程 | 16 ms 定时批量取最多 300 条刷新模型 | 禁止阻塞调用 |

队列有界（默认 100,000 包），满则丢弃并计数。**内核丢包（`ps_drop`）与队列丢弃语义不同，必须分开展示。**

## 数据流

```text
pcap_dispatch
  └─ 回调: string_at(data, caplen) → Packet(raw=memoryview)
       └─ BoundedPacketQueue.put()（满则 dropped += 1）
            ├─ CLI: 循环 drain(500) 打印摘要
            └─ GUI(P1): QTimer 每 16 ms drain(300)
```

## 关键约束

1. `Packet.raw` 是只读 `memoryview`，不复制到解析层；十六进制视图、导出、二次解析共用同一份字节。
2. `Packet.index` 全局单调递增，显示过滤后仍保留原值（`frame.number` 语义）。
3. 回调对象（`CFUNCTYPE` 实例）必须由后端持有强引用，否则被 GC 回收后回调会崩溃。
4. 回调内异常无法传播到调用方，必须整体 `try/except` 并计数（`callback_errors`）。
5. `pcap_compile` 成功后必须 `pcap_freecode`；失败时不得调用。
6. 停止采用 `timeout=100ms + pcap_dispatch(64)` 轮询 + `pcap_breakloop`：Windows 上 `breakloop` 不能立即唤醒阻塞循环。

## 目录职责

| 路径 | 职责 |
| --- | --- |
| `nps/capture/libpcap.py` | 纯绑定：结构体、签名、错误文本、库加载 |
| `nps/capture/pcap_backend.py` | 生命周期与分发循环；不做解析 |
| `nps/capture/interface.py` | 设备枚举与回环/伪设备判定 |
| `nps/capture/backend.py` | `CaptureBackend` 契约、`CaptureConfig`、`FakeBackend` |
| `nps/core/packet.py` | 包模型 |
| `nps/core/buffer.py` | 有界队列与丢弃计数 |
| `nps/__main__.py` | CLI；P1 起新增 `gui/` 入口 |

## 链路类型与头部布局（实测结论）

| 场景 | datalink | L3 偏移 | 说明 |
| --- | --- | --- | --- |
| 有线 / 无线 | `DLT_EN10MB`(1) | 14 | 标准以太网头，EtherType 在 12–13 |
| Npcap 回环 | `DLT_NULL`(0) | 4 | 前 4 字节是地址族（`02 00 00 00` = AF_INET），**不是以太网** |
| Linux SLL | `DLT_LINUX_SLL`(113) | 16 | 抓 `any` 伪设备时出现 |
| DLT_RAW | 12 / 101 | 0 | 无链路层头 |

`pcap_pkthdr` 在 WinPcap 4.1.3 与 Npcap 1.90（版本串标称 64-bit time_t）上**均为 32 位 time_t 布局**：
`ts_sec(4) + tv_usec(4) + caplen(4) + len(4) = 16 字节`，因此 `Timeval` 用 `c_long` 在两个版本上都正确。
该结论通过 dump 回调原始头部字节验证（见 `docs/DEVLOG.md`）。

## 已知边界

- 不做 TCP 重组：流视图以包为粒度；
- 不做 TLS 解密；
- 不做进程级归属（`Session.pid` 仅预留）；
- 离线与在线共用分发逻辑，但离线没有驱动统计，`stats().recv` 取已投递包数。
