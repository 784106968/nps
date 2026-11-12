# 架构说明

## 分层

```text
GUI                       PySide6：三窗格、过滤栏、会话视图、流时序图（P5）
   │  只读模型 / 只发命令
过滤层                    compile_filter → QSortFilterProxyModel（只影响显示）
   │
解析层                    decode：Ethernet/ARP/IPv4/IPv6/TCP/UDP/ICMP → 字段树 + 扁平字段表
   │
会话与识别层 (P3+)        五元组规范化、会话表、DPI
   │
核心层                    Packet 模型、定容存储、有界队列、统计
   │
捕获层                    ctypes → libpcap/Npcap 新 API
```

调用方向严格单向：上层依赖下层，下层不认识上层。捕获层与解析层不得 import GUI 或 Qt。

## 界面数据流

```text
捕获线程 ──put──▶ BoundedPacketQueue ──QTimer(16ms, ≤300 条)──▶ PacketTableModel
                                                                    │
                                     选中行 ──▶ decode_packet（惰性、缓存）│
                                                    ├──▶ DetailTree（字段树 + 偏移）
                                                    └──▶ HexView（原始字节 + 高亮）

                                     选中行/会话 ──▶ packets_of_stream（stream 索引）──▶ FlowView
```

- **惰性解析**：`data()` 只对可见行触发解析，结果按包序号缓存；20 万包不会在插入时全量解析。
  注意：启用显示过滤器后，`QSortFilterProxyModel` 需要对每个新行求值，会触发全量解码
  （见下方"已知边界"）。
- **容量淘汰**：模型在插入前用 `overflow_for()` 预判需要移除的行数，先 `beginRemoveRows`
  再丢弃，保证 Qt 的行号始终与存储一致。
- **字段高亮**：详情树节点存 `(offset, length)` 绝对偏移，HexView 直接按偏移绘制高亮块。

## 线程模型

| 线程 | 职责 | 约束 |
| --- | --- | --- |
| 捕获线程 | `pcap_dispatch` 循环 | 回调内只做 `string_at` 拷贝与入队，禁止解析/日志/IO |
| 解析线程（P3+，未启用） | 分层解析、会话聚合、DPI | 当前实际在 GUI 主线程按需惰性解析；后续启用时需保持 `Packet` 只读 |
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

## 会话模型（P3）

- **键**：`(proto, sorted_endpoint_a, sorted_endpoint_b)`，端点按 `(ip, port)` 排序，
  因此双向流量落在同一会话；ICMP 没有端口，端口位固定为 0。
- **stream_id**：从 1 单调递增；首次建表时的首包方向记为 `initiator`，据此判定上/下行。
- **记录内容**：首末时间、上下行包数与字节数、TCP 标志集合、首上行载荷（≤512 字节）、
  状态（进行中 / 关闭中 / 已关闭）、进程归属（`pid / process_name / process_confidence /
  process_note`，P6 Windows；需求见 [`PROCESS_ATTRIBUTION.md`](PROCESS_ATTRIBUTION.md)）。
- **老化**：TCP 120 s、UDP 60 s、ICMP/ICMPv6 30 s。`expire(now)` 接收显式时间，
  单元测试用虚拟时钟驱动；界面以「最后一个包的时间戳」为基准，
  避免回放旧 PCAP 时被系统时间误清空。
- **容量**：20,000 会话，超限按 LRU 淘汰并计数；淘汰不影响已显示的包。
- **不做重组**：`first_uplink_payload` 只取首个上行载荷，供 P4 的 DPI 使用。

会话表不依赖 `nps.decode` 的字段树：每包要做一次归表，因此单独做一次轻量解析
（IPv4/IPv6 头 + L4 端口），比构树快一个数量级。

## DPI（P4）

- 规则表 `nps/decode/dpi/signatures.json`，每条包含
  `protocol / direction / offset / pattern / description / kind`；
  `kind` 支持 `text`、`hex`、`dns_query`（结构化校验，避免把 DNS 响应误判为查询）。
- 匹配对象是会话的**首上行载荷**（并补充首下行载荷用于响应识别），失败再回落到端口启发式。
- 置信度只有两档：`dpi`（命中签名）与 `port`（仅端口）。端口先给初判，命中签名后升级为 `dpi`，
  一旦是 `dpi` 就不再重算。
- 结果挂在 `Session.app_protocol / confidence / classification_note` 上，包列表与会话列表共用；
  显示过滤的 `protocol` 字段优先取 `app_protocol`，因此 `protocol == http` 能命中 DPI 标签。
- 统计视图从会话表聚合（协议分布、会话 Top N），吞吐时间线由包模型按秒累加，
  两者与列表同源，不做二次统计。

### TLS 握手解析

`nps/decode/tls.py` 在 TCP 载荷上再做一层解析，只读**明文部分**：

| 层级 | 提取内容 |
| --- | --- |
| 记录层 | ContentType（握手/应用数据/告警）、Version、Length |
| 握手层 | ClientHello / ServerHello、Random、Session ID、Cipher Suites |
| 扩展 | `server_name`（SNI）、ALPN、supported_versions、supported_groups |

- 应用数据（ContentType=23）只标注 `N bytes（密文）`，不尝试解密；
- 记录跨 TCP 段时只解析首段，其余留白——这是"不做重组"的已知边界；
- 字段偏移均为帧内绝对偏移，选中 SNI 可直接在十六进制中高亮域名。

这也是讲义里"加密边界"的落地：抓得到包、读得出握手里的域名与套件，读不到正文。

## 流视图（P5）

`nps/gui/flow_view.py` 是只读消费者，不参与捕获与解析：

- **数据源**：`PacketTableModel.packets_of_stream(stream_id)` 返回该流的 `Packet` 引用列表。
  模型维护 `stream_id → 行号` 索引，按流取包是 O(k)；容量淘汰后索引标记失效，
  下一次插入时整体重建（行号整体前移），避免只重建半张表导致流视图少包；
- **方向判定**：复用 `nps.core.session.parse_flow` 做一次轻量 IP/L4 解析，
  源端点等于 `session.initiator` 记为上行，否则下行；
- **布局**：横轴是时间视窗，纵轴两端固定为客户端/服务端；每个包是一条贯穿两端的线，
  箭头指向接收方，线旁数字是 `wirelen`；
- **聚合**：当每包横向宽度 < 28 px 时按像素列合并（同列上下行各画半段），
  只保留 ≤ 图表宽度的列数；≥ 28 px 才逐包绘制文字与 TCP 标志；
- **交互**：滚轮以鼠标位置为锚点缩放（0.8 / 1.25），拖动平移，双击或 `0` 复位，
  `+` / `-` 键盘缩放；抓包追加时 `keep_view=True` 保留用户视窗；
- **性能**：10,000 包渲染 13.6 ms、100,000 包 177.7 ms，口径见 `docs/PERF.md`。

## 性能基线（P5）

`scripts/bench.py` 用同一五元组构造 1k/10k/100k 包，测量解析、会话归表、模型插入、
流构建、流渲染、详情树与 tracemalloc 峰值，结果归档在 `docs/PERF.md`。

关键优化：

| 优化 | 位置 | 效果 |
| --- | --- | --- |
| 惰性解析 + 按包序号缓存 | `PacketTableModel` | 只解析可见行，20 万包不在插入时全量构树 |
| 批量 `beginInsertRows` | `append_batch` | 100k 包约 712 ms（约 14 万包/秒） |
| 像素列聚合 | `FlowView._draw_dense` | 10k 点只画 ≤ 1,050 列，13.6 ms 完成 |
| `stream_id → 行号` 索引 | `PacketTableModel._stream_rows` | 按流取包 O(k)，拖动/缩放不扫全表 |
| 会话表 `version` + 快照缓存 | `SessionTable` | 空闲每秒刷新从 O(n) 降为 O(1) |
| `memoryview` 零拷贝 | `Packet.raw` | 十六进制/导出/二次解析共用同一份字节 |

## 进程归属（P6，Windows）

`nps/core/process_map.py` 把会话映射到本机进程，分三层：

| 层 | 职责 |
| --- | --- |
| `ProcessTable` | 与平台无关的快照与匹配：`exact[(proto, local_ip, port, remote_ip, port)]`、`by_port[(proto, local_ip, port)]`（值按 PID 去重）、`local_addrs` |
| `SystemResolver` | TTL 快照（2 s）、进程名缓存（30 s）、异常降级；Windows 表读取由 `_windows_table` 注入 |
| `create_resolver` | Windows 返回 `SystemResolver`，其他平台返回 `NullResolver` |

匹配顺序：先用 `local_addrs` 判断哪一端是本机，再查四元组（`exact`），
失败回退本地端口（`port`）；端口被多个进程共用时返回 `ambiguous` 且 PID 为空。
回环连接两端都是本机时，**优先归属发起方**（与 `Session.initiator` 一致）。

调用时机只有两处：会话首次创建、首个上行/下行载荷到达（服务端 accept 后
listener → worker 的刷新）。抓包回调与每包路径不调用 OS。

界面消费：会话面板「进程」列显示 `name (pid)`，tooltip 给出置信度与备注；
详情树追加「进程」节点；显示过滤提供 `process.pid` / `process.name`，
求值从 `session` 读取（谓词已带 `session` 参数），不把进程信息复制到每个 `Packet`。

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
- 进程归属只实现 Windows（`Session.pid` 有值），Linux `/proc` 方案暂缓；
- 显示过滤会对每个新行调用 `decode_packet` 求值，因此"过滤 + 20 万包"不是惰性的，
  这是当前实现的已知性能边界；
- 会话属性（DPI、进程归属）在首载荷/重试后更新，过滤器依赖会话版本变化重算；
- IPv6 扩展头（0/43/44/60）未在会话层跳过，这类包不进入会话（IPv6 分片等）；
- 离线与在线共用分发逻辑，但离线没有驱动统计，`stats().recv` 取已投递包数。
