# NPS — Network Packet Sniffer（实验 1A：带 GUI 的网络嗅探器）

> **术语澄清**：NPS = Network Packet Sniffer，本项目要交付的嗅探器；NPA = Network Protocol Analyzer，
> Wireshark 所属类别，是本项目在 NPS 达标之后的演进方向。二者不是同义词：NPS 决定"抓得到、抓得准、可过滤"，
> NPA 决定"看得全、看得深"。

> **合法使用声明**
> 使用本工具捕获网络流量，必须获得网络所有者、系统管理员或相关数据主体的明确授权。
> 未经授权截取、存储、分析或传播网络通信内容，在许多司法辖区可能承担法律责任。
> 本项目不提供规避授权、隐蔽监听或攻击性能力。捕获数据可能包含敏感信息，
> 导出或分享 PCAP 前应进行脱敏处理。本项目不实现 TLS 解密，也不进行中间人代理。

---

## 0. 交付约束（先读这一节）

### 0.1 硬约束

| 项目 | 要求 |
| --- | --- |
| 截止时间 | **2026-11-24**（含代码冻结、源码打包、演示与提交），自 2026-11-10 起共 14 个自然日 |
| 源码交付 | 可复现构建的源码压缩包，附 `SHA256SUMS.txt` 与 `BUILD.md` |
| 过程留痕 | 全流程在 GitHub 可见：Issue / Milestone / 分支 / PR / Commit / CI 运行记录 / Tag / Release |
| 捕获层 | **ctypes 直连 libpcap 新 API**（`pcap_create` → `pcap_activate`），不依赖第三方 Python 绑定 |
| 明确不做 | Wireshark 二次开发；完整 TCP 重组；TLS 解密；进程级流量归属（仅预留接口） |

### 0.2 评分口径与文档映射

| 评分口径（实验 1A） | 性质 | 对应阶段 | 本文档位置 |
| --- | --- | --- | --- |
| 实现 NPS（带 GUI 的网络嗅探器） | **红线**，未达成即不及格 | P0 + P1 | §5.1–§5.2 |
| 协议过滤能力（HTTP / TCP / UDP / IPv4 / IPv6 / ICMP + 逻辑演算） | 必须 | P0（BPF）、P2（显示过滤） | §3.4、§5.3 |
| 完善 NPA（会话、解析树、DPI、统计） | 加分，决定分数上限 | P3、P4 | §5.4–§5.5 |
| 流追踪：基于 IP + Port 的 TCP 流 | 加分 | P3 | §3.5、§5.4 |
| 流追踪：某进程产生的所有 TCP 流 | 加分 | 本期不实现，仅设计预留 | §3.6、§13 |
| 基于 Wireshark 二次开发 | 未采用 | — | §1.1 说明取舍 |

### 0.3 优先级铁律

1. **P0/P1 未通过验收，不得开启 P2。** P1 的 GUI 与解析验收通过（11/15，tag `v0.2.0`）即完成红线交付，此后任何问题都必须保证红线不被破坏。
2. 任一阶段超时 **超过 1 天**，立即执行 §11 降级预案，不得顺延挤占红线与打包窗口。
3. 11/23 起进入**冻结期**，只允许修复阻断性缺陷，不允许新增功能。
4. 功能完成度与"过程留痕"同等重要：commit 必须按日分布，禁止最后两天集中倾倒。

---

## 1. 项目定位

| 维度 | NPS（本项目的捕获内核） | NPA（本项目的分析目标） |
| --- | --- | --- |
| 核心目标 | 抓得准、跑得轻、可控过滤 | 看得全、看得深、可追踪 |
| 关键能力 | 接口枚举、BPF 捕获过滤、混杂模式、队列投递、统计丢包 | 协议解析树、会话表、DPI 识别、显示过滤、流追踪、导出 |
| 性能关注 | 捕获线程不阻塞、内核层过滤、批量 UI 刷新 | 解析可插件化、过滤可测试、流索引高效 |
| 交付形态 | 核心库 + 命令行 + GUI 后端 | 类 Wireshark 三窗格 GUI 与流视图 |

长期目标不是一次性复刻 Wireshark 的全部协议解析器，而是建立**可扩展的捕获—会话—解析—过滤—展示**骨架。

### 1.1 为什么不基于 Wireshark 二次开发

实验 1A 的考察点是"理解抓包层次、理解 libpcap 调用、自己实现过滤与解析"。基于 Wireshark 二次开发虽然工程上更省力，
但会绕开 `pcap_create/pcap_activate/pcap_compile/pcap_dispatch` 这条核心链路，也无法体现分层解码与会话聚合的实现过程，
与"必须实现 NPS"的考察目标不一致。因此本项目**自研捕获与解析**，Wireshark 仅作为**互操作性验证工具**
（导出的 PCAP 能被 Wireshark 正常打开即视为通过）。

---

## 2. 技术栈与依赖

- 语言：Python 3.10+
- GUI：PySide6（LGPLv3，与本项目 MIT 许可证兼容性最好；全项目统一，不再提供 PyQt6 分支）
- 捕获：**ctypes 直连** libpcap（Linux/macOS）/ wpcap.dll（Windows Npcap）
- 解析辅助：标准库 `struct`、`socket`、`ipaddress`、`dataclasses`
- 测试：`pytest`、`pytest-cov`；GUI 用 `PySide6.QtTest` + `offscreen` 平台（不额外引入 pytest-qt）
- 静态检查：`ruff`（必选）、`mypy`（可选，仅 core/decode 目录）
- CI：GitHub Actions（Ubuntu + Windows 双平台）
- 打包：`pyproject.toml` + `scripts/package.py`

### 2.1 为什么选 ctypes 新 API

| 方案 | 优点 | 缺点 | 结论 |
| --- | --- | --- | --- |
| `pcapy-ng` | 上手续快 | 只封装旧 API（`pcap_open_live`），无法设置 buffer / timeout / immediate mode；Windows 常需 MSVC 编译 | 弃用 |
| Scapy | 解析能力强，原型快 | 捕获层封装过厚，绕开 libpcap 调用细节；性能不可控 | 仅用于生成测试报文 |
| **ctypes 直连** | 完整掌控新 API、零额外依赖、可精确定位丢包原因 | 需自行声明结构体与回调签名 | **采用** |

### 2.2 依赖清单

```toml
[project]
requires-python = ">=3.10"
dependencies = []                       # 核心零第三方依赖

[project.optional-dependencies]
gui = ["PySide6>=6.6"]                  # P1 起启用，CI 不装
dev = ["pytest>=8", "pytest-cov>=5", "ruff>=0.6"]
```

> 说明：PySide6 作为可选附加项而非硬依赖，一是让 CI 与无 GUI 环境免于安装 100 MB+ 的 Qt，
> 二是避免解释器版本升级时被 GUI 库的 wheel 可用性卡住。

### 2.3 Windows 依赖说明

- 安装 Npcap 时勾选 **Support loopback traffic**（回环抓包依赖 `\Device\NPF_Loopback`）；
- 现代 Windows 项目**无需**勾选 "WinPcap API-compatible mode"；
- 回环适配器不支持混杂模式，接口枚举中需单独标注，避免用户误判"抓不到包"；
- **Npcap 不得随源码包或打包产物分发**（再分发需 OEM 授权），安装说明写入 README 与 `BUILD.md`；
- 无线网卡上"混杂模式"仅能收到本机相关帧，**混杂模式 ≠ 监控模式**，需在 UI 上给出提示。

---

## 3. 总体架构

```text
┌─────────────────────────────────────────────────────────────┐
│ GUI 层：PySide6                                              │
│ 包列表 QTableView + QAbstractTableModel                       │
│ 协议详情树 / 十六进制视图 / 会话列表 / 流时序图 / 统计 / 过滤栏 │
├─────────────────────────────────────────────────────────────┤
│ 会话与协议识别层                                              │
│ 五元组规范化 → 会话表 → 首上行载荷 DPI → 协议标签              │
│ 显示过滤器求值 → 流追踪索引 → 导出 / 离线打开                  │
├─────────────────────────────────────────────────────────────┤
│ 捕获层：ctypes → libpcap / wpcap.dll（新 API）                │
│ pcap_create → pcap_set_snaplen/buffer_size/timeout/promisc   │
│ → pcap_set_immediate_mode → pcap_activate                    │
│ → pcap_compile(BPF) → pcap_setfilter → pcap_dispatch         │
│ 回调只做拷贝与入队 → 有界队列 → GUI 批量消费                   │
└─────────────────────────────────────────────────────────────┘
```

### 3.1 捕获层 ctypes 绑定规范

**加载策略**

```python
import ctypes, os, sys
from ctypes import c_int, c_uint, c_long, c_char_p, c_void_p, c_ubyte, POINTER, Structure
from pathlib import Path

if sys.platform == "win32":
    # 必须用 CDLL：wpcap.dll 导出为 __cdecl，WinDLL 按 stdcall 解析，x86 下会栈错乱
    npcap = Path(os.environ.get("SYSTEMROOT", r"C:\Windows")) / "System32" / "Npcap"
    dll = npcap / "wpcap.dll"
    # 优先走 Npcap 目录：System32 下可能残留 2010 年的 WinPcap 4.x，裸名加载会被遮蔽
    _lib = ctypes.CDLL(str(dll) if dll.exists() else "wpcap.dll")
else:
    try:
        _lib = ctypes.CDLL("libpcap.so.1")
    except OSError:
        _lib = ctypes.CDLL("libpcap.so")
```

> 实战记录：本项目在 Windows 上首次运行时，`pcap_lib_version()` 返回
> `WinPcap version 4.1.3 ... 20091008`，说明按裸名加载的 `wpcap.dll` 被旧版遮蔽。
> 因此加载顺序必须是"先 Npcap 目录，再裸名"，并在 `--list-interfaces` 中显示实际版本，
> 否则 `pcap_set_immediate_mode` 等新 API 会静默缺失。

**必须声明的结构体与签名**（要点，完整实现放 `nps/capture/libpcap.py`）

```python
class Timeval(Structure):
    # Windows 上 time_t 为 32 位 long，必须用 c_long，不能用 c_int64
    _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]


class Pkthdr(Structure):
    _fields_ = [("ts", Timeval), ("caplen", c_uint), ("len", c_uint)]


_lib.pcap_create.argtypes = [c_char_p, c_char_p]  # device, errbuf
_lib.pcap_create.restype = c_void_p  # NULL 表示失败，errbuf 有原因
_lib.pcap_set_snaplen.argtypes = [c_void_p, c_int]
_lib.pcap_set_promisc.argtypes = [c_void_p, c_int]
_lib.pcap_set_timeout.argtypes = [c_void_p, c_int]  # 毫秒
_lib.pcap_set_buffer_size.argtypes = [c_void_p, c_int]  # 字节
_lib.pcap_set_immediate_mode.argtypes = [c_void_p, c_int]
_lib.pcap_activate.argtypes = [c_void_p]
_lib.pcap_activate.restype = c_int  # 0 成功；正数为告警；负数为错误
_lib.pcap_compile.argtypes = [c_void_p, POINTER(c_void_p), c_char_p, c_int, c_uint]
_lib.pcap_setfilter.argtypes = [c_void_p, c_void_p]
_lib.pcap_freecode.argtypes = [POINTER(c_void_p)]
_lib.pcap_dispatch.argtypes = [c_void_p, c_int, c_void_p, c_void_p]
_lib.pcap_next_ex.argtypes = [c_void_p, POINTER(POINTER(Pkthdr)), POINTER(POINTER(c_ubyte))]
_lib.pcap_datalink.argtypes = [c_void_p]
_lib.pcap_geterr.argtypes = [c_void_p]
_lib.pcap_geterr.restype = c_char_p
_lib.pcap_stats.argtypes = [c_void_p, c_void_p]  # struct pcap_stat { recv, drop, ifdrop }
_lib.pcap_breakloop.argtypes = [c_void_p]
_lib.pcap_close.argtypes = [c_void_p]
```

**调用序列（必须遵守）**

1. `pcap_create(device, errbuf)` → 句柄（NULL 时读 errbuf 抛 `CaptureError`）
2. `pcap_set_snaplen` / `pcap_set_promisc` / `pcap_set_timeout` / `pcap_set_buffer_size` / `pcap_set_immediate_mode`
3. `pcap_activate` → 返回值 < 0 视为失败，> 0 记录为 warning 并在 UI 提示但不中断
4. `pcap_datalink` → 选择链路层解码器（`DLT_EN10MB=1`、`DLT_LINUX_SLL=113`、`DLT_LINUX_SLL2=276`、`DLT_NULL=0`、`DLT_RAW=12/101`）
5. `pcap_compile` → `pcap_setfilter` → **`pcap_freecode`**（必须释放，否则每次换过滤器泄漏）
6. `pcap_dispatch(handle, 64, callback, None)` 循环取包
7. `pcap_breakloop` 停止 → `pcap_close` 释放

**关键参数默认值（可调，写入 UI 设置）**

| 参数 | 默认值 | 说明 |
| --- | --- | --- |
| snaplen | 65535 | 完整帧；性能敏感时可切 256（GUI 提供选项） |
| timeout | 100 ms | 决定 `pcap_dispatch` 返回周期，影响停止时延 |
| buffer_size | 8 MiB | 内核缓冲，过小会显著增加 `ps_drop` |
| immediate_mode | 0（关闭） | 关闭以批量交付、降低回调频率；低延迟场景可开 1 |
| promisc | 1（有线）/ 0（回环、无线） | 回环适配器设置无效，需跳过 |

**回调实现约束**

```python
CALLBACK = ctypes.CFUNCTYPE(None, c_void_p, POINTER(Pkthdr), POINTER(c_ubyte))


def _on_packet(user, hdr, data):
    h = hdr.contents
    raw = ctypes.string_at(data, h.caplen)  # 指针在下一次取包后失效，必须立即拷贝
    try:
        queue.put_nowait(Packet(ts=..., caplen=h.caplen, wirelen=h.len, raw=raw))
    except queue.Full:
        dropped.increment()
```

- 回调内**禁止**任何解析、格式化、日志、文件 I/O、加锁等待；
- `put_nowait` 失败即计数丢弃，不得阻塞捕获线程；
- 回调为 C 调用进入 Python，会争用 GIL，因此批量大小 64 + 队列批量消费是必需的，不是优化项；
- `CALLBACK(...)` 创建的实例**必须保存为后端对象的属性**，被 GC 回收后再回调会直接使进程崩溃（ctypes 高频踩坑点）；
- 回调内抛出的 Python 异常会被吞掉且无法传播，因此回调体必须整体 `try/except` 并计数，不允许任何可能抛异常的调用。

**停止机制（Windows 专项）**

Windows 上 `pcap_breakloop` 不能立即唤醒阻塞中的 `pcap_loop`，需等待超时或下一个包。因此统一采用：
`timeout=100ms` + `pcap_dispatch(cnt=64)` 轮询 + `pcap_breakloop` 置位，保证**停止响应 ≤ 500 ms**。
禁止使用无限期阻塞的 `pcap_loop`。

**其他约束**

- `pcap_dispatch` 与 `pcap_next_ex` 二选一，全项目统一用 `pcap_dispatch`（批量语义更好）；
- 每次 `pcap_compile` 后必须 `pcap_freecode`；
- 在线与离线（`pcap_open_offline`）共用同一 `Packet` 生产接口，便于测试回放；
- `pcap_stats` 的内核丢包（`ps_drop`）与队列丢弃必须**分开展示**，二者语义不同。

**两个已实测的坑（P0 验证结论）**

- **回环设备不是以太网**：Npcap 的 `\Device\NPF_Loopback` 上报 `DLT_NULL`(0)，帧首 4 字节是地址族
  （`02 00 00 00` = AF_INET），L3 头部从偏移 4 开始。若一律按 14 字节以太网头解析协议号，
  会得到"抓到包但全部解析不出协议"的假象，且空集合断言容易造成假阳性。
- **`pcap_pkthdr` 布局**：Npcap 1.90 的版本串虽标称 `64-bit time_t`，但 dump 回调头部可见
  偏移 8 / 12 分别是 caplen / len，说明结构仍是 32 位 time_t 布局（16 字节）。`Timeval` 用 `c_long`
  在 WinPcap 4.1.3 与 Npcap 1.90 上均正确；若未来版本改变布局，`caplen` 会出现明显异常的巨值。

### 3.2 数据模型

```python
@dataclass(slots=True)
class Packet:
    index: int  # 全局递增序号，过滤后仍保留原序号
    ts: float  # 秒（含小数）
    caplen: int  # 捕获长度
    wirelen: int  # 线路长度
    linktype: int  # DLT_*
    raw: memoryview  # 只读原始字节，供十六进制视图 / 导出 / 二次解析
    layers: dict | None  # 解析结果缓存，首次解析后填充
    stream_id: int | None
    protocol: str | None
    confidence: str | None  # "port" | "dpi"
```

**存储策略（必须实现，否则内存失控）**

- 包数据放入**固定容量环形缓冲**，默认上限 **200,000 包**；超出覆盖最旧包并在 UI 顶部提示"已丢弃 N 条旧记录"；
- `raw` 使用 `bytes` 包装的 `memoryview` 切片，**不复制**到解析层；
- 十六进制视图与导出直接读 `raw`，因此**"只保留摘要"是错误设计**，必须保留原始字节；
- 会话表与包表分离计数，内存上限写入 `docs/PERF.md` 基线表。

### 3.3 线程模型（必须遵守）

- **捕获线程**：跑 `pcap_dispatch` 循环，回调仅拷贝入队（见 §3.1）。
- **解析/会话线程（P3 起启用）**：从队列取包做分层解析、会话聚合、DPI 匹配，结果写回共享结构。
- **GUI 主线程**：`QTimer` 每 16 ms 批量取最多 300 条更新模型；禁止在 GUI 线程执行阻塞捕获。
- 队列**必须有界**（默认 100,000 包），满则丢弃并计数，UI 展示"内核丢包 / 队列丢弃"两项。
- 所有跨线程结构使用 `queue.Queue` 或加锁的环形缓冲，禁止裸 `list` 共享。

### 3.4 过滤体系

**捕获过滤（BPF，内核态）**

`pcap_compile` 阶段下推，只有匹配流量进入用户态。示例：`tcp port 80`、`udp and host 192.168.1.10`、
`icmp`、`tcp[tcpflags] & tcp-syn != 0`。编译失败时通过 `pcap_geterr` 取回原始错误并原样展示（不要吞掉）。

**显示过滤（用户态）**

作用于已捕获包，不重新抓包。语法：

```ebnf
expr       := or_expr
or_expr    := and_expr ( "||" and_expr )*
and_expr   := unary ( "&&" unary )*
unary      := "!" unary | primary
primary    := "(" expr ")" | comparison
comparison := field op value
op         := "==" | "!=" | "<" | "<=" | ">" | ">="
value      := integer | "quoted string" | identifier | cidr
```

**字段与语义（值域必须固定，供 GUI 提示与文档共用）**

| 字段 | 类型 | 语义 | 示例 |
| --- | --- | --- | --- |
| `ip.src` / `ip.dst` | IPv4/IPv6 地址 | 源/目的地址（字符串精确匹配） | `ip.src == 10.0.0.5` |
| `ip.proto` | int 或名称 | 6=tcp、17=udp、1=icmp、58=icmpv6 | `ip.proto == icmp` |
| `ip.addr` | 地址或 CIDR（P2 可选） | 源或目的任一命中 | `ip.addr == 192.168.0.0/16` |
| `tcp.port` | int | **源或目的任一**端口 | `tcp.port == 443` |
| `tcp.srcport` / `tcp.dstport` | int | 定向端口 | `tcp.dstport == 80` |
| `tcp.flags.syn` | 0/1 | SYN 标志 | `tcp.flags.syn == 1` |
| `udp.port` / `udp.srcport` / `udp.dstport` | int | 同上 | `udp.port == 53` |
| `icmp.type` / `icmp.code` | int | ICMP 类型/代码 | `icmp.type == 8` |
| `protocol` | 字符串（大小写不敏感） | `HTTP`/`TLS`/`SSH`/`DNS`/`BT`/`TCP`/`UDP`/`ICMP`/`ARP`/`IPv6` 等 | `protocol == http` |
| `stream_id` | int | 会话编号 | `stream_id == 12` |
| `frame.len` / `frame.number` | int | 线路长度 / 包序号 | `frame.len > 1000` |

- 比较运算两侧类型不匹配视为**表达式错误**（不是空结果集），必须提示用户；
- `protocol == HTTP` 依赖 DPI 标签，未识别出协议的包不参与匹配（GUI 需注明）；
- 求值器放在核心层（`filters/evaluator.py`），GUI 只传表达式字符串，保证可单元测试。

### 3.5 会话与流追踪

- 规范化键：`(端点A_IP, 端点A_端口, 端点B_IP, 端点B_端口, 协议)`，端点按 (IP, 端口) 排序后拼接，保证双向同键；
- `stream_id` 从 1 单调递增；首次建表时的首包方向定义为 **initiator**，据此判定上行/下行；
- 会话记录：首/末包时间、上下行包数与字节数、TCP 标志集合、首上行载荷（前 512 字节）、状态、协议标签与置信度；
- **老化与容量（必须实现）**：

| 会话类型 | 结束条件 | 空闲老化 |
| --- | --- | --- |
| TCP | 双向 FIN 或收到 RST | 120 s |
| UDP | — | 60 s |
| ICMP | 请求-应答配对完成 | 30 s |
| 其他 | — | 60 s |

  容量上限 **20,000** 会话，超限按 LRU 淘汰并计数，UI 可见。
- 第一版**不做 TCP 重组**；流时序图以"包"为粒度，不承诺消息边界（见 §13）。
- 会话表按 `pcap_datalink` 无关的方式工作，仅依赖解析出的 IP/TCP/UDP 层。

### 3.6 为 NPA 预留的扩展点（P1 就必须落地）

| 扩展点 | 位置 | 目的 |
| --- | --- | --- |
| 原始字节只读视图 | `Packet.raw` | 十六进制、导出、后续二次解析免复制 |
| 解析结果缓存 | `Packet.layers` | 避免重复解析，支撑详情树 |
| 解码器注册表 | `decode/registry.py` | P4 插件化零改造 |
| 会话增量统计 | `Session` 字节/包计数字段 | 图表直接消费，避免全量重算 |
| 进程归属占位 | `Session.pid` + `ProcessResolver` 接口 | 后续实现"某进程的所有 TCP 流"时不改模型 |

> `ProcessResolver` 本期只有接口定义与 `NullResolver`（恒返回 None），**不实现任何 OS 调用**。
> 会话视图可保留一列"进程"，值为"—"。

---

## 4. 推荐目录结构

```text
nps/
├── README.md
├── LICENSE
├── SECURITY.md
├── CONTRIBUTING.md
├── BUILD.md                    # 可复现构建与打包说明
├── CHANGELOG.md
├── pyproject.toml
├── Makefile                    # 常用命令入口（lint/test/package/bench）
├── docs/
│   ├── CONCEPTS.md             # OSI 分层、抓包点、加密边界、思考题
│   ├── ARCHITECTURE.md
│   ├── DEVELOPMENT.md
│   ├── FILTER_SYNTAX.md
│   ├── DEVLOG.md               # 每日开发日志（过程留痕）
│   ├── PERF.md                 # 性能基线记录
│   └── DECISIONS.md            # 关键技术决策记录（ADR）
├── nps/
│   ├── __init__.py
│   ├── __main__.py
│   ├── capture/
│   │   ├── backend.py          # CaptureBackend 协议 + FakeBackend（CI 用）
│   │   ├── libpcap.py          # ctypes 签名、结构体、错误封装
│   │   ├── pcap_backend.py     # 新 API 调用序列实现
│   │   ├── interface.py        # 设备枚举（含 NPF_Loopback 标注）
│   │   └── dump.py             # 实时落盘（pcap_dump_*）
│   ├── core/
│   │   ├── packet.py
│   │   ├── buffer.py           # 环形缓冲与容量上限
│   │   ├── session.py          # 五元组会话表 + 老化
│   │   ├── flow.py             # 流索引与同流查询
│   │   ├── stats.py            # 捕获/队列/会话统计
│   │   └── process_map.py      # 进程归属接口占位（本期不实现）
│   ├── decode/
│   │   ├── registry.py
│   │   ├── link.py             # Ethernet / 802.1Q / SLL
│   │   ├── arp.py
│   │   ├── ipv4.py
│   │   ├── ipv6.py
│   │   ├── icmp.py
│   │   ├── tcp.py
│   │   ├── udp.py
│   │   └── dpi/
│   │       ├── signatures.json
│   │       └── matcher.py
│   ├── filters/
│   │   ├── capture_filter.py   # BPF 编译封装
│   │   ├── lexer.py
│   │   ├── parser.py
│   │   └── evaluator.py
│   ├── gui/
│   │   ├── main_window.py
│   │   ├── packet_model.py
│   │   ├── detail_tree.py
│   │   ├── hex_view.py
│   │   ├── session_view.py
│   │   ├── stats_view.py
│   │   ├── flow_view.py        # 流时序图
│   │   └── filter_bar.py
│   └── pcapio/
│       └── pcapfile.py         # 离线读写（避免与标准库 io 同名）
├── scripts/
│   ├── probe_pcap.py           # ctypes 冒烟探针（D0 必须先跑通）
│   ├── make_fixtures.py        # 生成合成 PCAP
│   ├── bench.py                # 性能基线
│   └── package.py              # 生成源码包 + SHA256
└── tests/
    ├── unit/
    ├── integration/
    └── fixtures/               # 合成 PCAP，不含真实敏感流量
```

**文档产出对照（每个文件都必须有归属阶段，避免出现"结构里有、任务里没有"）**

| 文件 | 产出阶段 | 负责人动作 |
| --- | --- | --- |
| `README.md` | 11/10 | 建库时完成，全程维护 |
| `LICENSE` / `SECURITY.md` / `CONTRIBUTING.md` | 11/10 | 初始化即建，11/23 复核 |
| `docs/CONCEPTS.md` | 11/15–11/16 | 分层与加密边界说明 |
| `docs/ARCHITECTURE.md` | 11/13 初稿 / 11/19 补充 | 架构与数据流、会话模型 |
| `docs/DEVELOPMENT.md` | 11/15–11/16 | 环境、权限、故障排查 |
| `docs/FILTER_SYNTAX.md` | 11/17 | 与求值器同步 |
| `docs/DEVLOG.md` | 11/10 起每日 | 完成 / 阻塞 / 次日计划 |
| `docs/PERF.md` | 11/22 | 性能基线数据 |
| `docs/DECISIONS.md` | 11/22 | 3 条关键决策 |
| `docs/DEMO.md` | 11/22 | 演示脚本 |
| `BUILD.md` / `CHANGELOG.md` | 11/23 | 构建校验与变更记录 |

---

## 5. 分阶段开发计划（14 天）

日程总览：

| 日期 | 阶段 | 主要产出 | GitHub 动作 |
| --- | --- | --- | --- |
| 11/10（二） | P0-1 | 仓库、许可证、README、pyproject、ruff、pytest、CI、里程碑、`probe_pcap.py` 跑通 | 建库 + 6 个 Issue + Milestone，首个 PR 合入 |
| 11/11（三） | P0-2 | 接口枚举（含 `NPF_Loopback` 标注）、设备描述 | PR #2，tag `v0.1.0` |
| 11/12（四） | P0-3 | ctypes 绑定全量封装、参数配置、BPF 编译、stats、停止机制 | PR #3 |
| 11/13（五） | P1-1 | 有界队列、环形缓冲、实时落盘 | PR #4 |
| 11/14（六） | P1-2 | 三窗格骨架、包列表模型、QTimer 批量刷新 | PR #5 |
| 11/15（日） | P1-3 | 基础解析（Eth/ARP/IPv4/IPv6/TCP/UDP/ICMP/VLAN）+ 十六进制联动 | PR #6，tag `v0.2.0`（**红线达成**） |
| 11/16（一） | P1-4 | 离线 PCAP 读取与回放、合成 fixtures | PR #7 |
| 11/17（二） | P2-1 | 显示过滤（词法/语法/求值）+ 过滤栏 | PR #8 |
| 11/18（三） | P3-1 | 会话表（规范化、老化、容量）+ `stream_id` | PR #9 |
| 11/19（四） | P3-2 | 同流高亮、会话视图、跳转 | PR #10，tag `v0.3.0` |
| 11/20（五） | P4-1 | DPI 签名与协议标签（HTTP/TLS/SSH/BT） | PR #11 |
| 11/21（六） | P4-2 | 详情树结构化 + 统计图 | PR #12 |
| 11/22（日） | P5 | 流时序图、性能优化、性能基线报告 | PR #13，tag `v0.9.0` |
| 11/23（一） | 打包 | 源码包、SHA256、BUILD.md、演示录屏、DEVLOG 收尾、安全审查 | Release `v1.0.0` |
| 11/24（二） | 缓冲 | 仅修阻断性缺陷，最终提交 | 最终 tag + 提交确认 |

### 5.1 P0：捕获内核（11/10–11/12，红线前置）

**任务**

- [x] `pyproject.toml`、`requirements.txt`、`ruff`、`pytest`、`Makefile` 就位；
- [x] `LICENSE`（MIT）、`SECURITY.md`、`CONTRIBUTING.md`、`.github/workflows/ci.yml` 就位；
- [x] `scripts/probe_pcap.py`：加载库、打印 `pcap_lib_version`、枚举设备、读一个包后退出（**这一天必须跑通，否则后续全盘阻塞**）；
- [x] `CaptureBackend` 协议（`open/start/stop/close/stats`）+ `FakeBackend`；
- [x] 设备枚举：名称、描述、是否回环、是否支持混杂模式；
- [x] 新 API 调用序列 + 参数配置 + 错误信息透传（`pcap_geterr`）；
- [x] BPF 编译与设置，编译错误原文展示；
- [x] `pcap_stats` 读取与解析；
- [x] 停止机制（timeout + dispatch 轮询 + breakloop）；
- [x] 命令行模式打印摘要，验证过滤与混杂模式生效。

**验收（量化）**

- `probe_pcap.py` 在 Windows 与 Linux 均能枚举设备并打印版本；
- 指定 `icmp` 后只收到 ICMP 包，指定 `tcp port 80` 后只收到对应包；
- 非法表达式报错信息与 `pcap_geterr` 一致，程序不崩溃；
- 开始→停止响应 ≤ 500 ms，重复 20 次无泄漏（句柄数不增长）；
- `FakeBackend` 可在无 Npcap 环境下驱动全链路，CI 绿灯。

### 5.2 P1：GUI 与基础解析（11/13–11/16，**红线交付**）

**任务**

- [x] 三窗格 `QSplitter` 布局：包列表 / 详情树 / 十六进制；
- [x] 包列表 `QAbstractTableModel`：序号、时间、源、目的、协议、长度、摘要；
- [x] 开始/暂停/停止、接口选择、BPF 输入、清空、自动滚动；
- [x] `QTimer` 批量消费（16 ms / 300 条）；
- [x] 解析：Ethernet、802.1Q、ARP、IPv4、IPv6、TCP、UDP、ICMP（v4/v6）；
- [x] 详情树按层展开，十六进制视图选中包联动、选中字节高亮；
- [x] 环形缓冲容量上限与丢弃提示（20 万包，超限淘汰最旧并计数）；
- [x] "另存为 PCAP"（含敏感数据确认；导出后可被 libpcap 读回）；
- [ ] 实时落盘（`pcap_dump` 流式写入）—— 顺延至 P3，当前采用"停止后导出"；
- [x] 离线 PCAP 读取（供测试与回放，GUI 打开入口可后置）；
- [x] `docs/CONCEPTS.md`：OSI 分层与抓包点（AF_PACKET 在 netfilter 之前）、链路层/网络层/应用层可见范围、TLS 加密边界；
- [x] `docs/DEVELOPMENT.md`：环境搭建、Windows/Linux 权限差异、常见故障（抓不到包 / `ps_drop` 高 / 回环无流量）；
- [x] `docs/ARCHITECTURE.md` 初稿：分层职责、数据流（回调 → 队列 → 解析 → 模型）、线程边界。

**验收（量化）**

- 回环复放合成 PCAP，≥ 5,000 pps 持续 60 s：UI 无 > 500 ms 卡顿，队列丢弃率 < 1%；
- 20 万包满载时进程内存 < 800 MB；
- 暂停语义明确：**停止刷新但仍抓包**（UI 显示"暂停刷新中，仍在捕获 N 包"）；
- 十六进制视图字节偏移与详情树字段偏移一致（抽样 20 个包人工核对）；
- 导出 PCAP 可被 Wireshark 打开且包数与列表一致。

**实测（2026-11-10，Windows 10 + Npcap 1.90）**：回环 UDP 5,000 pps 持续 10 s，表内 49,875 包，
队列丢弃 0，UI 帧间隔 中位 15.8 ms / p95 21.8 ms / **max 49.1 ms**（预算 500 ms），内存 59 → 120 MB；
全量测试 89 项通过（含 6 条 GUI 联动与 1 条界面端到端抓包）。

### 5.3 P2：显示过滤（11/17，必须项）

**任务**

- [ ] 词法分析（`lexer.py`）：标识符、数字、字符串、比较符、`&&`、`||`、`!`、括号；
- [ ] 语法分析（`parser.py`）：优先级 `!` > 比较 > `&&` > `||`；
- [ ] 求值器（`evaluator.py`）：字段解析、类型校验、空值语义；
- [ ] 字段覆盖 §3.4 全部字段（含 `icmp.type`、`ip.proto`、`protocol`）；
- [ ] 过滤栏实时校验，错误定位到字符位置；
- [ ] 过滤后包序号保持原值，流追踪索引不受影响；
- [ ] `docs/FILTER_SYNTAX.md` 同步更新。

**验收（量化）**

- 单元测试 ≥ 25 条，覆盖运算符优先级、括号、取反、类型错误、空结果；
- `protocol == http` 能筛出 DPI 标记为 HTTP 的包，并排除未识别包；
- 错误表达式不抛栈到 UI，只显示中文提示 + 原文。

### 5.4 P3：会话表与流追踪（11/18–11/19，加分主力）

**任务**

- [ ] 五元组规范化、双向合并、`stream_id` 分配；
- [ ] 会话统计字段、老化定时器、容量上限与 LRU；
- [ ] 首上行载荷提取（≤ 512 字节）；
- [ ] TCP 标志状态记录；
- [ ] 点击包 → 高亮同流；双击 → 跳转会话；
- [ ] 会话视图：五元组、上下行包/字节、时长、协议、进程列（"—"）；
- [ ] `docs/ARCHITECTURE.md` 补充会话模型与老化策略。

**验收（量化）**

- 合成 PCAP 中一条完整 TCP 连接（握手 + 数据传输 + 四次挥手）合并为 **1 个** `stream_id`，上下行包数误差为 0；
- 2 万会话压测内存 < 200 MB，超限淘汰计数可见；
- 老化逻辑用虚拟时钟单元测试覆盖（TCP FIN/RST、UDP 空闲）。

### 5.5 P4：DPI 与 NPA 增强（11/20–11/21）

**任务**

- [ ] `signatures.json`：`(protocol, direction, offset, pattern, description)`；
- [ ] 至少支持：HTTP 请求行/`Host:`、TLS ClientHello、SSH `SSH-2.0-`、BitTorrent 握手、DNS 查询；
- [ ] 端口启发式初筛（标注为 `port` 置信度，不得当作确定结论）；
- [ ] 包列表与详情树展示协议标签 + 置信度来源；
- [ ] 详情树字段可复制；
- [ ] 统计视图：协议分布、会话 Top N、吞吐时间线（数据与列表一致）。

**验收（量化）**

- fixtures 中每类协议各 ≥ 1 组正样本，识别正确率 100%；≥ 5 组负样本，误标率 < 5%；
- 统计数值与列表实际计数一致（同一数据源，不允许二次统计）。

### 5.6 P5：流视图与性能（11/22）

**任务**

- [ ] 流时序图（`flow_view.py`）：横轴时间、纵轴两端，标注方向与包长，支持缩放；
- [ ] 性能优化：批量解析、模型增量更新、避免深拷贝；
- [ ] `scripts/bench.py` + `docs/PERF.md` 记录 1k/10k/100k 包下帧率、内存、丢包；
- [ ] `docs/DEMO.md`：5 分钟演示脚本（选网卡 → BPF → 抓包 → 详情 → 十六进制 → 显示过滤 → 同流 → 导出）。

**验收（量化）**

- 10,000 包的流时序图渲染 ≤ 1 s；
- 详情树展开 ≤ 100 ms；
- 性能表格归档，与 §5.2 阈值对比结论明确。

---

## 6. GitHub 过程留痕规范（评分可见项）

**仓库结构**

- `main` 为受保护分支：需 PR + CI 通过 + 至少 1 次自查记录；
- Milestone：`v1.0.0 — 实验 1A 交付`；每个阶段建 1 个 Issue，Issue 内用 checklist 拆分任务并回填 §5 的验收标准；
- Label：`p0`/`p1`/`p2`/`p3`/`p4`/`p5`、`capture`、`gui`、`filter`、`docs`、`blocked`。

**分支与提交**

- 分支：`feat/capture-ctypes`、`feat/gui-three-pane`、`feat/display-filter`、`fix/<topic>`、`docs/<topic>`、`chore/<topic>`；
- 提交：Conventional Commits，如 `feat(capture): add pcap_activate error mapping`；
- **每个自然日至少 1 次有意义的提交**，11/23–11/24 不得集中提交（会被视为无效过程留痕）；
- 禁止 `push --force` 到 `main`，禁止跳过 CI 合并。

**PR 模板（`.github/pull_request_template.md`）**

```text
## 变更内容
## 关联 Issue（Closes #N）
## 验证方式（命令 / 截图 / 录屏链接）
## 风险与回滚
## 自查清单（lint 通过 / 单测通过 / 文档已更新）
```

GUI 相关 PR 必须附截图；捕获层 PR 必须贴 `probe_pcap.py` 输出。

**CI（`.github/workflows/ci.yml`）**

- 矩阵：`ubuntu-latest` + `windows-latest`，Python 3.10 / 3.12；
- 步骤：`ruff check` → `pytest -m "not requires_npcap"` → 覆盖率报告；
- 需要真实网卡/Npcap 的用例打 `@pytest.mark.requires_npcap`，本地运行并将日志贴到 PR；
- `windows-latest` 无 Npcap，因此**所有跨平台逻辑必须能跑在 `FakeBackend` 上**。

**过程证据文件**

- `docs/DEVLOG.md`：每日一条（完成 / 阻塞 / 次日计划），与提交记录互为印证；
- `docs/PERF.md`：性能基线数据表；
- `docs/DECISIONS.md`：至少 3 条决策记录（ctypes vs pcapy-ng、PySide6 选型、进程追踪是否实现）。

**Tag 与 Release**

`v0.1.0`（P0 完成）→ `v0.2.0`（红线达成）→ `v0.3.0`（会话追踪）→ `v0.9.0`（功能完成）→ `v1.0.0`（交付）。

---

## 7. 测试策略

| 层级 | 范围 | 要求 |
| --- | --- | --- |
| 单元测试 | 过滤器（词法/语法/求值）、五元组规范化、会话老化、DPI 匹配、PCAP 读写边界 | 整体覆盖率 ≥ 60%，`filters/` 与 `core/session.py` ≥ 80% |
| 集成测试 | `FakeBackend` → 队列 → 解析 → 模型 全链路；离线 PCAP 回放 | 无外部依赖，CI 必跑 |
| 真实设备测试 | 回环 + 物理网卡抓包、BPF 生效、混杂模式 | `requires_npcap` 标记，本地执行并留档 |
| GUI 冒烟 | 三窗格结构、选中联动、字段字节高亮、清空、真实抓包入表 | `PySide6.QtTest` + `offscreen`；未安装 PySide6 时整组跳过 |
| 性能基线 | 1k / 10k / 100k 包 | 结果写入 `docs/PERF.md`，与阈值对比 |

**测试数据原则**：只用 `scripts/make_fixtures.py` 生成的合成 PCAP 或明确授权的流量，**不得提交真实抓包**。

**关键测试清单（必须有）**

1. 非法 BPF 表达式错误路径；
2. 过滤器运算符优先级与括号；
3. 过滤器类型不匹配报错；
4. 双向流合并为同一 `stream_id`；
5. 会话老化与 LRU 淘汰；
6. 环形缓冲溢出后序号连续性；
7. 截断包（`caplen < len`）解析不越界；
8. 畸形 PCAP（长度字段异常）不崩溃；
9. `FakeBackend` 注入丢包时计数正确；
10. 导出 PCAP 重新读取后包数一致。

---

## 8. 打包与交付

**打包脚本 `scripts/package.py`**

- 基于 `git archive` 生成 `nps-1.0.0-src.zip`，天然排除 `.venv`、`__pycache__`、`.pytest_cache`、本地 PCAP；
- 附 `SHA256SUMS.txt`；
- 同一压缩包上传为 GitHub Release 附件，保证"交付件 = 仓库快照"可校验。

**包内必须包含**

`README.md`、`LICENSE`、`SECURITY.md`、`CONTRIBUTING.md`、`BUILD.md`、`CHANGELOG.md`、
`pyproject.toml`、`docs/*`、`tests/fixtures/*.pcap`（合成）、`scripts/*`。

**可复现验证（写入 `BUILD.md`）**

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest -m "not requires_npcap"
python -m nps --version
```

在**干净环境**下执行一次并记录结果；Windows 另记一条（含 Npcap 安装前提）。

**演示材料**

- `docs/DEMO.md`：5 分钟演示脚本（选网卡 → BPF 过滤 → 抓包 → 详情树 → 十六进制 → 显示过滤 → 同流高亮 → 导出）；
- 演示录屏（存 Release 说明或仓库外链），覆盖红线功能与至少 1 个加分功能。

**明确不做**：不在压缩包内附带 Npcap 安装包或 `wpcap.dll`；不附带任何真实流量。

---

## 9. 开发规范

- 分支与提交见 §6；
- 审查：每个 PR 至少一次自查（对照 Issue 验收标准逐条勾选），捕获/解析/过滤/导出路径改动必须附带测试；
- 代码风格：`ruff format` + `ruff check`，行宽 100；
- 类型：`core/`、`decode/`、`filters/` 使用类型注解，`mypy` 报告不得新增错误；
- 禁止在 GUI 线程做解析或 I/O；
- 新增字段/过滤器语法必须同步更新 `docs/FILTER_SYNTAX.md` 与测试。

---

## 10. 快速开始（开发环境）

```bash
git clone https://github.com/<your-org>/nps.git
cd nps
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows（PowerShell）
# .venv\Scripts\Activate.ps1

pip install -e ".[dev]"
python -m nps --list-interfaces
python -m nps                      # 启动 GUI
pytest -m "not requires_npcap"
```

**权限说明**

- Linux：需要 `CAP_NET_RAW` 与 `CAP_NET_ADMIN`（后者用于设置混杂模式）。推荐：
  `sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))`，或直接以 `sudo` 运行；
- Windows：安装 Npcap（勾选 loopback 支持），若安装时启用"限制为管理员"，则需以管理员身份运行；
- macOS：需以 `sudo` 运行，`/dev/bpf*` 权限受限。

**无环境快速验证**：`python -m nps --offline tests/fixtures/http_basic.pcap` 可在无抓包权限下验证解析与 UI。

---

## 11. 风险登记册与降级预案

| 风险 | 概率 | 影响 | 预案 |
| --- | --- | --- | --- |
| ctypes 结构体/回调签名错误导致崩溃 | 中 | 高（阻塞全盘） | D0 用 `probe_pcap.py` 单独验证；签名集中一处；崩溃即回退到最小可跑序列 |
| Windows `pcap_breakloop` 停止延迟 | 高 | 中 | 统一 100 ms timeout + dispatch 轮询，停止 ≤ 500 ms |
| 回调竞争 GIL 导致 UI 卡顿 | 高 | 中 | 批量 64 + 队列 + 16 ms/300 条刷新 + 列表容量上限 |
| 内存随包数线性增长 | 高 | 中 | 环形缓冲 20 万上限 + 会话 LRU 淘汰 |
| 时间不足 | 中 | 高 | 按下方顺序降级，红线不受影响 |
| 无线网卡抓不到目标流量 | 中 | 低 | UI 明确提示"混杂模式 ≠ 监控模式"，文档说明限制 |
| 真实流量合规风险 | 低 | 高 | 全程仅用回环 + 合成 PCAP，演示前清空真实数据 |

**降级顺序（从先砍到后砍）**

1. P5 流时序图（保留统计图与性能记录）
2. P4 统计图表（保留详情树结构化）
3. P4 DPI 缩减为 HTTP + TLS + SSH（去掉 BitTorrent/DNS）
4. P3 会话视图降级为包列表附加列（保留 `stream_id` 与同流高亮）

**不可降级项**：P0 捕获内核、P1 三窗格 GUI 与基础解析、P2 显示过滤（PDF 必须项）、导出 PCAP、源码打包。

**触发规则**：当日计划未完成且预计次日仍无法补齐 → 当天立即执行降级，并在 `DEVLOG.md` 记录原因，不允许"先欠着后面补"。

---

## 12. 安全与合规清单（11/23 统一执行）

- [ ] `LICENSE` 使用 SPDX 标识符（MIT），与 PySide6（LGPLv3）兼容；
- [ ] `SECURITY.md` 含漏洞报告渠道、授权使用边界、脱敏建议；
- [ ] README 显著位置保留合法授权声明与"不实现 TLS 解密"说明；
- [ ] 对不可信 PCAP 解析路径做长度与边界校验（§7 清单 7、8 已覆盖）；
- [ ] 不默认上传、不默认持久化捕获数据，导出需显式操作；
- [ ] 明确 Npcap 许可证与"不随包分发"约束；
- [ ] Release 附已知限制与安全注意事项；
- [ ] `pip-audit` 本地执行一次并记录结果（不阻塞 CI）。

> 说明：CodeQL / Dependabot / 多平台安全门禁属于长期维护成本，14 天窗口内不作为任务项，仅在 Release 说明中标注为后续计划。

---

## 13. 已知边界与后续方向

- **不做完整 TCP 重组**：流时序图以包为粒度，不承诺应用层消息边界；需要时再引入独立重组模块（乱序、重传、重叠片段）。
- **不做 TLS 解密**：加密边界不可逾越。Thor 类工具依赖终端安装根证书并作为中间人，本质是端点解密而非"破解传输"；本项目明确不提供该能力，只提取可见元数据（如 SNI）。
- **不做进程级流量归属**：`Session.pid` 与 `ProcessResolver` 仅为接口占位，UI 显示"—"。若后续实现：Windows 走 `GetExtendedTcpTable`，Linux 走 `sock_diag` + `/proc/<pid>/fd` inode 匹配；需处理权限、端口复用、进程退出与 IPv6，属于独立工时（估 1–1.5 天）。
- **DPI 只提高置信度**：端口启发式必须标注为 `port`，不得表述为确定结论。
- **无线监控模式**与有线混杂模式机制不同，需单独文档化，本期不实现。
- 后续可选方向：离线流式解析、解析器插件化、更多应用层协议、零拷贝采集（AF_PACKET TPACKET_V3 / PF_RING 不属于本期范围）。

---

## 14. 许可证

本项目采用 MIT 许可证，详见 `LICENSE`。
使用本工具即表示你理解并同意：仅在获得明确授权的网络与系统上使用。
