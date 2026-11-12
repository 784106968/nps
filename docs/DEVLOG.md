# 开发日志

> 每日一条：完成 / 决策 / 阻塞 / 数据 / 次日计划。与 commit 记录互为印证。

## 2026-11-10（周二）｜D0：仓库基线 + 捕获内核

### 完成

- 仓库基线：`pyproject.toml`、`requirements.txt`、`Makefile`、`ruff`、`pytest`、`.gitignore`；
- 合规文件：`LICENSE`（MIT）、`SECURITY.md`、`CONTRIBUTING.md`、`README.md`；
- CI：GitHub Actions 双平台矩阵（ubuntu/windows × py3.10/3.12），PR 与 Issue 模板；
- ctypes 绑定层 `nps/capture/libpcap.py`：结构体、函数签名、错误封装、库加载与诊断；
- 捕获后端 `PcapBackend`：`create → set_* → activate → compile → setfilter → dispatch → breakloop → close`；
- 设备枚举 `nps/capture/interface.py`：回环、伪设备识别与默认设备选择；
- 有界队列 `nps/core/buffer.py`：满即丢弃并计数，绝不阻塞捕获线程；
- `FakeBackend`：无驱动环境下驱动整条链路，作为 CI 的测试替身；
- CLI `python -m nps`：`--list-interfaces`、`-i`、`-f`、`-c`、`--duration`、`--offline`、`-v`；
- 工具脚本：`scripts/probe_pcap.py`（冒烟探针）、`scripts/make_fixtures.py`（合成 PCAP）；
- 测试：50 条单元测试 + 5 条离线集成测试。

### 关键决策

1. **捕获层用 ctypes 直连新 API**：`pcapy-ng` 只封装 `pcap_open_live` 旧接口，无法设置 buffer / timeout / immediate mode。
2. **Windows 优先加载 `System32\Npcap\wpcap.dll`**：本机 System32 下残留 WinPcap 4.1.3（2010 年），按裸名加载会被它遮蔽，导致 `pcap_set_immediate_mode` 等新 API 缺失。
3. **PySide6 改为可选依赖**（`pip install -e ".[gui]"`）：核心零第三方依赖，CI 无需安装 GUI 库；P1 开始前再启用。
4. **离线回放提前到 P0 实现**：无驱动时，离线与在线共用同一套 `pcap_dispatch` 与回调，是验证 ctypes 链路正确性的手段；装上驱动后它仍是 P1 的测试基础。

### 环境处理：安装 Npcap 1.90

初始状态：`System32\wpcap.dll` 是 2013 年的 WinPcap 4.1.3 残留，`npcap` / `npf` 驱动服务均不存在，`pcap_findalldevs` 返回 0 个设备。

处理过程与踩坑：

1. **静默安装失败**（退出码 2）：Npcap 免费版不支持 `/S`，安装器提示 "silent installation is only supported in Npcap OEM"，必须走图形向导。
2. **WinPcap 残留阻塞安装**：卸载 WinPcap 4.1.3 后，`System32` 仍留有 `wpcap.dll` / `packet.dll`，Npcap 检测到后仍会中止；把两个 DLL 移动到 `%TEMP%\winpcap-backup`（可回滚）后安装成功。
3. **安装结果**：Npcap 1.90（libpcap 1.10.7，64-bit time_t），驱动 `npcap` 已 RUNNING，枚举到 12 个设备，`\Device\NPF_Loopback` 正确标注为回环。

### 实测数据（P0 验收）

| 项目 | 命令 | 结果 |
| --- | --- | --- |
| 设备枚举 | `python -m nps --list-interfaces` | Npcap 1.90，12 个设备，含 `NPF_Loopback` |
| 冒烟探针 | `probe_pcap.py -i <Wi-Fi 网卡> --wait 5` | 激活成功 DLT_EN10MB；5 秒捕获 79 包；`ps_drop=0`；停止 0.3 ms |
| 过滤器 udp | `scripts/verify_p0.py` | 300/300 包均为 UDP，无混入 |
| 过滤器 icmp | 同上 | 8/8 包均为 ICMP，无混入 |
| 过滤器 tcp port 80 | 同上 | 抓包期间只发 UDP，捕获 0 包 |
| 非法表达式 | 同上 | `can't parse filter expression: syntax error`，进程不崩溃 |
| 停止时延 ×20 | 同上 | min 0.3 / 中位 0.3 / p95 0.5 / max 0.5 ms（预算 500 ms） |
| 负载 2000 包 | 同上 | 捕获 2000，`ps_recv=2000`，`ps_drop=0`，队列丢弃 0 |
| 线程泄漏 | 同上 | 5 轮 start/stop 后线程数 1 → 1 |
| 离线回放 | `python -m nps --offline ...` | 6 包，`ps_recv=6`，EOF 自动退出 |
| 全量测试 | `pytest` | 59 passed（含 4 条真实网卡用例） |
| 静态检查 | `ruff check .` | All checks passed |

### 两个结构体层面的实证

1. **`pcap_pkthdr` 仍是 32 位 time_t 布局（16 字节）**。版本串虽然写着 "64-bit time_t"，但 dump 原始头部得到
   `00 f1 53 65 | 00 00 00 00 | 3a 00 00 00 | 3a 00 00 00`，偏移 8 与 12 分别是 caplen/len（58/58），
   说明 Npcap 为兼容 WinPcap ABI 未改变该结构。`c_long` 的写法在 WinPcap 4.1.3 与 Npcap 1.90 上均正确。
2. **回环设备上报 `DLT_NULL`（0），不是以太网**。帧首 4 字节是地址族 `02 00 00 00`，L3 头从偏移 4 开始。
   若一律按 14 字节以太网头解析，会误判协议号——`verify_p0.py` 第一版就因此出现"0 包 UDP 却判定通过"的假阳性，
   已改为按 `packet.network_offset` 计算偏移，并在断言中加入"计数必须大于 0"。

---

## 2026-11-10（周二）｜P1：Wireshark 风格三窗格界面

提前于计划（原定 11/13–11/16），当日完成红线交付内容。

### 环境确认

| 项 | 值 |
| --- | --- |
| Python | 3.14.7 |
| PySide6 / Qt | 6.12.0 / 6.12.0 |
| 平台插件 | `windows`（1 块屏幕），CI 用 `offscreen` |
| 安装方式 | `pip install -e ".[gui]"`（可选依赖，核心与 CI 不引入 Qt） |

缺少 PySide6 时 `run_gui()` 返回 1 并提示 `pip install -e ".[gui]"`，由单元测试固定该行为。

### 完成

- **解析层** `nps/decode/`：Ethernet II / 802.1Q / DLT_NULL / DLT_LINUX_SLL / DLT_RAW，
  ARP、IPv4、IPv6、TCP、UDP、ICMP(v4/v6)；每层带字段树与**帧内绝对偏移**，供详情树与十六进制联动；
  解析器整体 `try/except` 兜底，单个畸形包不会影响界面。
- **存储** `nps/core/store.py`：定容 20 万包，超限淘汰最旧并计数。
- **列表模型** `nps/gui/packet_model.py`：7 列（No./Time/Source/Destination/Protocol/Length/Info），
  **惰性解析**（仅解析被显示或被选中的包），协议列着色。
- **详情树** `nps/gui/detail_tree.py`：按层展开，选中字段发出 `(offset, length)`。
- **十六进制** `nps/gui/hex_view.py`：自绘 16 字节/行 + ASCII 列，支持任意字节区间高亮与自动滚动。
- **主窗口** `nps/gui/main_window.py`：`QSplitter` **垂直三窗格**、面板标题条、可拖动分隔条；
  工具栏含接口选择、BPF 过滤器、开始/停止/暂停/清空/保存/自动滚动；状态栏显示包数、队列积压、丢弃与内核丢包。
- **导出** `nps/pcapio/`：另存为 PCAP（导出前有敏感数据确认），产物可被 libpcap 读回。
- **CLI**：无参数默认启动 GUI，`--cli` 保留命令行模式。

### 交互语义

| 动作 | 行为 |
| --- | --- |
| 选中列表某行 | 详情树重建、十六进制加载该帧，偏移 0 对齐 |
| 选中详情树字段 | 十六进制高亮对应字节（如 TCP 目的端口 → 偏移 36，长度 2） |
| 暂停 | 停止从队列取包，列表冻结，状态栏显示积压；继续时自动加速追赶 |
| 停止 | 抓包线程退出，把队列剩余包补进列表后刷新状态 |

### 实测数据

| 项目 | 结果 |
| --- | --- |
| 回环 UDP 压测 | 5,000 pps × 10 s → 表内 49,875 包，队列丢弃 **0** |
| UI 帧间隔 | 中位 15.8 ms / p95 21.8 ms / **max 49.1 ms**（预算 500 ms） |
| 内存 | 59 MB → 120 MB（约 1.2 KB/包，含原始字节与解析缓存） |
| 自动化测试 | **89 passed**（含 6 条 GUI 联动、1 条界面端到端抓包） |
| 静态检查 | `ruff check` / `ruff format --check` 通过 |

### 问题与修正

1. **列宽不生效**：`setSectionResizeMode` 会重置列宽，且拉伸列索引误用"宽度数组长度"（6）而非"列数"（7），
   导致 Protocol 列被拉伸、Length 列被吞掉。改为先设模式、再设宽度，拉伸列取 `len(COLUMNS) - 1`。
2. **一次性灌包超过容量时不淘汰**：`PacketStore.extend` 原先只从已有数据里丢，空表灌 5 个进容量 3 仍是 5 条。
   改为"先追加再统一裁剪"，并让 `total_seen` 统计全部接收量。
3. **离屏截图全是方框**：`QT_QPA_PLATFORM=offscreen` 下字体库为空，属渲染环境限制；
   截图改用 `windows` 平台完成，界面本身无需改动。

### 未完成（顺延）

- 抓包过程中**实时落盘**（`pcap_dump` 流式写）：当前实现是"停止后另存为"，顺延至 P3；
- GUI 内直接打开离线 PCAP（CLI 已支持 `--offline`），计划随 P3 的"打开文件"入口一并做。

### 次日计划（P2）

- 显示过滤：词法/语法/求值三层拆分，字段覆盖 `icmp.type`、`ip.proto`、`protocol`、`stream_id`；
- 运算符 `== != < <= > >= && || !` 与括号，优先级 `!` > 比较 > `&&` > `||`；
- 过滤栏实时校验与错误定位，`docs/FILTER_SYNTAX.md` 同步。

---

## 2026-11-11（周三）｜P2：显示过滤

### 完成

- **三层实现**：
  `lexer.py`（标识符/整数/字符串/IP 字面量/运算符，带字符位置）、
  `parser.py`（递归下降，优先级 `!` > 比较 > `&&` > `||`）、
  `evaluator.py`（字段表、编译期类型检查、谓词求值）、
  `display_filter.py`（对外 `compile_filter`）。
- **字段 24 个**：`ip.src/dst/addr/proto/version/len/ttl`、`tcp.port/srcport/dstport/flags.syn/flags.ack/len`、
  `udp.*`、`icmp.type/code`、`arp.op`、`protocol`、`stream_id`、`frame.len/number`；`ip.addr` 支持 CIDR。
- **解码层**新增 `Decoded.fields` 扁平字段表，解析时顺带写入，过滤器不再二次解析原始字节。
- **界面**：第二行「显示过滤器」，250 ms 防抖，回车立即生效；错误时输入框变红、右侧显示"第 N 列：原因"、
  状态栏同步提示，且**上一条有效规则继续生效**；状态栏同时显示「包数 / 显示」。
- **代理模型**：过滤不删包，清空表达式立即恢复，`No.` 保持抓包时的全局序号。
- 文档 `docs/FILTER_SYNTAX.md`：文法、字段表、多值语义、示例与错误示例。

### 实测数据

| 项目 | 结果 |
| --- | --- |
| 全量测试 | **130 passed**（新增 40 条：词法 5、语法 6、求值 22、类型错误 7） |
| 过滤生效 | 6 包中 `ip.src == 192.168.1.10 && (tcp.port == 80 \|\| icmp.type == 8)` → 显示 3 包 |
| 错误提示 | `ip.srcc == 1` → 「第 1 列：未知字段 'ip.srcc'」，列表保持上一条规则的 3 行 |
| 静态检查 | `ruff check` / `ruff format --check` 通过 |

### 问题与修正

1. **IP 字面量被拆碎**：`10.0.0.1` 原先被词法器读成 `INT(10)` + 未知字符 `.`。
   改为在数字/标识符分支里按地址字符集（`0-9a-f:./`）整体扫描，识别出 `IP` 类型 token；
   顺带支持 `fe80::1`、`::1`、`10.0.0.0/8`。
2. **文本字段与数字比较未报错**：`protocol == 80` 原本能编译且恒为假，违反"类型不匹配即错误"的约定；
   补上校验，报「字段 protocol 需要字符串，得到数字 80」。
3. **Qt 6.12 弃用告警**：`invalidateFilter()` 与 `invalidateRowsFilter()` 均被标记弃用，改调公共 `invalidate()`。

### 未完成

- `protocol == http` 这类应用层判断依赖 P4 的 DPI；当前 `protocol` 只到 L3/L4（TCP/UDP/ICMP/ARP）。
  `FILTER_SYNTAX.md` 已注明：DPI 落地前请用 `tcp.port == 80`。

### 次日计划（P3）

- 五元组规范化与双向合并、`stream_id` 分配；
- 会话统计（上下行包/字节、首末时间、TCP 状态）与老化（FIN/RST、UDP 空闲）；
- 2 万会话容量与 LRU 淘汰；同流高亮与会话视图。

---

## 2026-11-11（周三）｜P3：会话表与流追踪

### 完成

- **会话表** `nps/core/session.py`：
  端点按 `(ip, port)` 排序拼键，双向流量合并；`stream_id` 从 1 递增，首包方向记为 initiator；
  统计上下行包数与字节、TCP 标志集合、首上行载荷（≤512 B）、状态（进行中 / 关闭中 / 已关闭）；
  老化 TCP 120 s、UDP 60 s、ICMP 30 s；容量 20,000，LRU 淘汰并计数。
- **轻量流解析**：不调用 `decode_packet`（不构字段树），只读 IPv4/IPv6 头与 L4 端口，
  每包一次归表的成本远低于完整解析。
- **进程归属占位** `nps/core/process_map.py`：`ProcessResolver` 协议 + `NullResolver`，
  会话记录 `pid` 字段，界面显示「—」，为后续实现留好接口。
- **界面**：右侧「会话」停靠面板（流 / 协议 / 会话 / 包 ↑↓ / 字节 ↑↓ / 时长 / 状态 / 进程），
  单击会话高亮该流，双击跳到首包；选中任意包时整条流在列表中浅蓝高亮；
  状态栏新增「流: N」；鼠标悬停显示完整会话与 Info 文本。

### 实测数据

| 项目 | 结果 |
| --- | --- |
| 全量测试 | **150 passed**（新增 20 条：会话 14、界面 6） |
| 完整握手 | 8 个 TCP 包（SYN/SYN-ACK/ACK/PSH×2/FIN×2/ACK）→ **1 个 stream_id**，上行 5 / 下行 3 |
| 容量与内存 | 20,000 会话峰值 **17.2 MB**，约 902 B/会话（预算 200 MB） |
| 老化 | 虚拟时钟：UDP 60 s、TCP 120 s、ICMP 30 s 边界各一条用例 |
| 界面 | 3 条会话（TCP + 2 UDP），过滤后 6/8 包可见，选中包后同流 6 行全部高亮 |

### 问题与修正

1. **会话面板初始太窄**：列被挤掉、出现横向滚动条。给 `QDockWidget` 设 620 最小宽度，
   用 `resizeDocks` 给 700 默认宽度，并压缩列宽。
2. **老化基准不能用系统时间**：离线回放旧 PCAP 时，包时间戳是历史时间，
   用 `time.time()` 会立刻清空全部会话。改为以「最后一个包的时间戳」为基准。
3. **上下行计数断言写错**：界面用例只喂了 6 个包（SYN / SYN-ACK / ACK / PSH-ACK / PSH-ACK / FIN-ACK），
   正确结果是上行 4、下行 2，我一开始按 8 包场景写成了 5 / 1，被测试当场纠正。

### 未完成

- **进程归属**仍是占位（`pid` 恒为 None），需要 OS 接口，估 1–1.5 天，本期不做；
- **TCP 重组**不做，`first_uplink_payload` 只取首包载荷，供 P4 DPI 用。

### 次日计划（P4）

- `signatures.json` 与 DPI 匹配器：HTTP 请求行 / TLS ClientHello / SSH / BitTorrent / DNS；
- 端口启发式仅作初筛并标注 `port` 置信度；
- 详情树字段复制、协议分布与会话 Top N 统计。

---

## 2026-11-11（周三）｜P4：DPI 与 NPA 增强

### 完成

- **签名表** `nps/decode/dpi/signatures.json`：13 条规则
  （HTTP 请求行 6 种方法 + 响应行 + `Host:` 头、TLS 握手、SSH ×2、BitTorrent、DNS 查询），
  字段为 `protocol / direction / offset / pattern / description / kind`。
- **匹配器**：`text` / `hex` / `contains` / `dns_query` 四种方式；
  DNS 走结构化校验（QR=0、qdcount=1、QNAME 可解析），避免把响应误判为查询。
- **会话集成**：端口先给 `port` 初判，命中签名升级为 `dpi`，一旦 `dpi` 不再重算；
  结果挂在 `Session.app_protocol / confidence / classification_note`。
- **界面**：
  协议列显示最高层协议（HTTP/TLS/…），悬停给出「置信度 + 依据」；
  详情树底部追加应用层节点（置信度、识别依据）；
  字段支持右键「复制值 / 复制字段」与 `Ctrl+C`。
- **统计视图**（与会话面板同为右侧页签）：协议分布、会话 Top 10、吞吐时间线；
  协议分布与 Top N 从会话表聚合，时间线由包模型按秒累加，均与列表同源。
- `docs/FILTER_SYNTAX.md` 更新：`protocol` 为最高层协议，传输层改用 `ip.proto`。

### 实测数据

| 项目 | 结果 |
| --- | --- |
| 全量测试 | **179 passed**（新增 29 条：DPI 23、界面 6） |
| 正样本 | HTTP GET/POST、TLS ClientHello、SSH、BitTorrent、DNS 查询全部命中 |
| 负样本 | 空载荷、随机 48 字节、`SSH-3.0`、`GET`（过短）、DNS 响应、伪 BitTorrent 均未误判 |
| 6 包样本 | 识别为 HTTP / HTTP / TLS / DNS / SSH / UDP，5 条会话 |
| 统计一致性 | 协议分布包数之和 == 会话表包数之和（测试断言） |

### 问题与修正

1. **`protocol == tcp` 不再命中 HTTP 流**：DPI 之后 `protocol` 表示最高层协议，这是预期语义，
   但容易踩坑。补了 `ip.proto == tcp` 的说明与测试，文档同步。
2. **Qt6 弃用 `setTextAlignment(int)`**：改传 `Qt.AlignmentFlag` 重载。
3. **时间线只有 2 个数据点时柱条铺满整屏**，且峰值文字被遮挡：限制柱宽 16px、居中排布，
   绘图区顶部留 22px 给标题。

### 追加（同日）：TLS 握手解析

原计划外，起因是"HTTPS 到底能看到什么"这个问题。

- 新增 `nps/decode/tls.py`：记录层（ContentType/Version/Length）→ 握手层
  （ClientHello/ServerHello、Random、Cipher Suites）→ 扩展（SNI、ALPN、supported_versions）；
- `tcp.py` 在载荷以 TLS 记录开头时追加一层；应用数据只标 `N bytes（密文）`，不尝试解密；
- 真实抓包验证（Wi-Fi，`curl https://example.com`）：解析出 `SNI=example.com`、
  `ALPN=http/1.1`、ClientHello → ServerHello → 3 段 Application Data；
  同批流量里还解析出 `copilot.tencent.com` 及 `TLS 1.3` 支持列表；
- 选中 SNI 字段时十六进制高亮偏移 117、长度 11，与字节完全对齐。

### 未完成

- TLS 记录跨 TCP 段时只解析首段（本项目不做重组）；
- 证书链不解析：TLS 1.3 起证书本身已加密，只有 TLS 1.2 及以下能看到明文证书。

### 次日计划（P5）

- 流时序图（横轴时间、纵轴两端，标注方向与包长）；
- 性能优化与 `docs/PERF.md` 基线；
- `docs/DEMO.md` 五分钟演示脚本。

## 2026-11-12（周四）｜P5：流时序图与性能基线

### 完成

- `nps/gui/flow_view.py`：横轴时间、纵轴两端（上=客户端、下=服务端），
  箭头表示方向，线旁标注 `wirelen`；稀疏时显示 SYN/FIN/RST/PSH，
  滚轮以鼠标为锚点缩放、拖动平移、双击或 `0` 复位、`+`/`-` 键盘缩放；
- 主窗口右侧新增「流时序图」页签，与「会话」「统计」并列；
  选中包或点击会话即联动，抓包追加时保留用户当前缩放（`keep_view=True`）；
- 性能优化：
  1. `PacketTableModel` 维护 `stream_id → 行号` 索引，按流取包从 O(N) 降为 O(k)；
  2. `SessionTable` 增加 `version` 与快照缓存，会话面板刷新从每秒 O(n) 签名计算降为 O(1)；
  3. 流视图密集时按像素列聚合，10k 点只画 ≤ 1,050 列；
- `scripts/bench.py`：1k/10k/100k 包的解析、会话归表、模型插入、流构建、流渲染、
  详情树与 tracemalloc 峰值，支持 `--json` 与 `--repeat`；
- `docs/PERF.md`、`docs/DEMO.md`；`README.md` 状态表、`NPS-Readme.md` §5.6 勾选、
  `docs/ARCHITECTURE.md` 增补流视图与性能章节。

### 实测数据（P5 验收）

| 项目 | 阈值 | 实测 | 结论 |
| --- | --- | --- | --- |
| 10,000 包流渲染 | ≤ 1 s | **13.60 ms** | 通过 |
| 详情树展开 | ≤ 100 ms | **0.18 ms** | 通过 |
| 100,000 包内存 | 20 万包 < 800 MB | **57.88 MB**（Python 对象，外推 200k ≈ 116 MB） | 通过 |
| 解析吞吐 | 5,000 pps 不卡顿 | 12,902–21,814 包/秒（最坏全量构树） | 通过 |
| 队列丢弃 | 5,000 pps 下 < 1% | 100k 容量正常速率不触发；200k 灌入按预期丢弃 100k | 通过 |

### 关键决策

1. **流视图不复制 `raw`**：`packets_of_stream` 返回 `Packet` 引用，方向判定复用
   `parse_flow` 的轻量解析，避免为绘图再存一份字节。
2. **密集聚合而非抽样**：抽样会漏掉突发与重传，按像素列合并能保留"某时刻有包"的事实，
   同时把绘制量压到图表宽度级别。
3. **不做 per-session 包缓存**：只在选中时构建 `FlowPoint`，切换会话即释放；
   10 万点约 10 MB，换取不为所有会话常驻内存。
4. **保留 `keep_view`**：抓包时每秒刷新不会重置用户缩放，否则放大观察握手时会被"弹回"。

### 问题与修正

1. **`QPixmap` 渲染计时必须在 `paintEvent` 路径上量**：直接测 `set_flow` 只覆盖数据构建，
   验收要求的是"渲染"，因此 bench 与测试都走 `QWidget.render()`。
2. **同列上下行混合**：若只按主导方向着色，会把一问一答画成单色；
   改为上半段蓝色（上行）、下半段绿色（下行）。
3. **文档与实现偏差**：`ARCHITECTURE.md` 原写"解析线程（P3+）从队列批量取包"，
   实际解码仍在 GUI 主线程惰性执行；本次更正为"未启用"，避免交付文档失真。

### 环境恢复（同日）

重装系统后 `C:\Python314` 与 Npcap 均不存在，`.venv` 的 `pyvenv.cfg` 指向已删除的解释器：

- 重装 Python 3.12.9（对齐 CI 的 `windows-latest × 3.12`），删除旧 `.venv` 重建；
- 重装 Npcap 1.90（勾选 loopback），`probe_pcap.py` 全过，停止时延 0.1 ms；
- `.pytest_cache` 的所有者仍是旧系统 SID，普通权限无法删除；
  管理员执行 `takeown` + `icacls /reset` 后移除，pytest 缓存恢复正常。

### 次日计划（收尾）

- 全量回归（预计 195 条）与 `ruff check`/`format --check`；
- 按 `NPS-Readme.md` §7 生成源码压缩包、`SHA256SUMS.txt` 与 `BUILD.md`；
- 用 `docs/DEMO.md` 走一遍现场流程，确认桌面快捷方式启动正常。

## 2026-11-12（周四）｜P6：进程归属（Windows）

### 完成

- `nps/core/process_map.py`：`ProcessTable`（四元组 + 端口匹配、`local_addrs` 判定本机端）、
  `SystemResolver`（TTL 2 s 快照、进程名缓存 30 s、异常降级）、`NullResolver`；
- Windows ctypes 直连 `GetExtendedTcpTable` / `GetExtendedUdpTable`（IPv4 + IPv6），
  进程名用 `QueryFullProcessImageNameW`，失败时只显示 PID；
- `Session` 增加 `process_name / process_confidence / process_note`，
  `SessionTable` 在**创建会话**与**首个载荷**时各查询一次，服务端 accept 后可从 listener 刷新为 worker；
- 会话面板「进程」列显示 `name (pid)`，tooltip 给出 `exact / port / ambiguous` 依据；
  详情树追加「进程」节点；状态栏显示归属可用性与连接数；
- 显示过滤新增 `process.pid` / `process.name`，谓词从 `session` 取值，未复制到 `Packet`；
- `scripts/probe_process.py` 自检；
- 测试：匹配规则/缓存/降级/过滤 12 条、会话归属 6 条、界面 5 条、Windows 回环集成 4 条；
- 文档：需求文档、架构、过滤语法、开发说明与 P6 计划同步。

### 实测数据

| 项目 | 结果 |
| --- | --- |
| 本机连接快照 | **367 条精确连接 / 6 个本机地址**，刷新 **4.1 ms** |
| 回环 TCP 归属 | PID 与 `python.exe` 均正确，`confidence=exact`，刷新 2.7 ms |
| 全量测试 | **222 passed**（新增 27 条） |
| 静态检查 | `ruff check .` 全过 |

### 关键决策

1. **不枚举本机 IP**：快照自带 `local_addrs`，先判断哪一端是本机，再查四元组；
   抓镜像口时两端都不在表内，直接放弃归属而不是猜。
2. **进程信息只挂在会话上**：20 万包不重复存进程名；过滤谓词本就会收到 `session`，
   因此不需要改 `Packet` 或代理模型。
3. **回环连接归属发起方**：两端都是本机时，`(src,dst)` 正向优先，与 `Session.initiator` 语义一致；
   服务端进程可通过端口回退看到，但默认显示发起方。
4. **冲突宁可不归属**：同端口多进程返回 `ambiguous`，PID 为空，界面显示「端口冲突」。

### 问题与修正

1. **`status_text` 先判断 `_table` 导致读取失败时显示"正在初始化"**：
   改为先看 `_note`，失败时明确显示"不可用（读取失败：…）"。
2. **UDP 没有对端地址**：`GetExtendedUdpTable` 不提供 remote，因此 UDP 只做端口匹配，
   置信度固定为 `port`；文档与 UI 同步标注，不表述为确定结论。
3. **快照刷新可能落在 GUI 线程**：TTL 2 s + 只在会话边界触发，实测单次 3–4 ms，
   不会打破 16 ms 帧预算；若后续连接数显著增长，可移到后台线程（已留 `refresh(force)` 接口）。

### 未完成

- Linux `/proc/net` + `/proc/<pid>/fd` 实现（按计划搁置，方案在需求文档 §4）；
- 进程启动时间校验（PID 复用增强）、代理/容器识别、按进程统计与 CSV 导出。

### 次日计划

- P6 分支提交、PR 与 CI 回归；
- 现场用浏览器/`curl` 验证进程列与 `process.name` 过滤；
- 视时间决定是否启动 Linux 版本（当前不排期）。
