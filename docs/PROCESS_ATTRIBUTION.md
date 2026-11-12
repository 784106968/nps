# 进程归属（Process Attribution）需求说明

> 状态：**Windows 已实现（P6，2026-11-12）**；Linux 方案保留，**暂缓实现**。
> 对应 `NPS-Readme.md` §3.6 的预留扩展点、§5.7 的 P6 计划与 §13 的已知边界。

## 1. 背景与现状

P3 已预留两个占位：

| 占位 | 位置 | 当前行为 |
| --- | --- | --- |
| `Session.pid` | `nps/core/session.py` | 恒为 `None`，会话面板显示「—」 |
| `ProcessResolver` | `nps/core/process_map.py` | 只有 `Protocol` 与 `NullResolver`，**无任何 OS 调用** |

现有基础对实现有利的部分：

- 会话表已完成五元组规范化，双向流量合并为同一个 `stream_id`；
- 会话已记录 `initiator`、上下行包数/字节、TCP 状态、首载荷；
- 显示过滤的谓词已接受 `session` 参数（`filterAcceptsRow` 会传入），
  新增 `process.*` 字段不需要改包模型或代理模型；
- 核心层坚持**零第三方依赖**，因此 Windows 用 ctypes 直调 `iphlpapi`，Linux 读 `/proc`。

## 2. 功能目标与使用场景

**目标**：把**本机**抓到的 TCP/UDP 会话映射到产生它的本机进程，回答"这条连接是谁发的"。

| 场景 | 说明 |
| --- | --- |
| 故障排查 | 某进程持续外连、异常上传/下载，定位到可执行文件 |
| 安全自查 | 发现未知进程的外联行为（需授权环境） |
| 教学演示 | 展示"五元组 → socket → 进程"的完整映射链路 |
| 过滤与统计 | 只看某进程的流量：`process.name == chrome.exe` |

**明确不做（需求预期管理）**：

- 不能归属**对端主机**的进程——只能看到本机 socket 表；
- 不能归属**离线 PCAP** 的历史流量（进程可能早已退出）；
- 不做内容审计、TLS 解密、进程行为拦截；
- 不承诺识别代理/VPN/容器内真实应用（只标注可见进程与置信度）。

## 3. 判定规则

### 3.1 基本流程

1. **取包的端点**：从 `parse_flow` 已产出的 `(src, sport)`、`(dst, dport)` 与协议号出发，
   先用快照的 `local_addrs` 判断哪一端是本机，再以 `(本机端点 → 对端端点)` 查询四元组；
   两端都不在本机地址表（抓镜像口/他机流量）时直接放弃，不猜测。
2. **匹配优先级**：

| 优先级 | 键 | 置信度 | 适用 |
| --- | --- | --- | --- |
| 1 | `(proto, local_ip, local_port, remote_ip, remote_port)` | `exact` | TCP established，含客户端与服务端 accepted 连接 |
| 2 | `(proto, local_ip, local_port)` | `port` | UDP、TCP 监听 socket（无对端或对端未知） |
| 3 | 失败 | `none` | 返回 `None`，不猜测 |

3. **写入时机**：会话**首次创建**时解析一次；首个上行或下行**载荷**到达时再解析一次
   （服务端 accept 后连接从 listener 转移到 worker，需要刷新）。
   未拿到 `exact` 之前，会话**每秒重试一次**，直到命中或会话结束；
   避免快照 TTL 窗口内建立的连接永久为空。
4. **缓存**：连接快照 TTL **2 s**（可配置），未命中时强制刷新（全局节流 0.5 s）；
   `pid → 进程名` TTL 30 s；抓包线程不触发快照刷新，由会话层按需惰性刷新。

### 3.2 边界情况

| 情况 | 处理 |
| --- | --- |
| ICMP / ICMPv6 | 无端口，OS 表也不提供 owner，直接 `None` |
| ARP / 非 IP | `None` |
| IPv6 与双栈 | 快照同时读 `AF_INET` 与 `AF_INET6`；v4-mapped 地址统一归一化 |
| 端口复用（`SO_REUSEADDR` / `SO_REUSEPORT`） | 四元组优先；仅端口命中且存在多个候选时标记 `ambiguous`，返回 `None` 并记 note |
| 监听进程 vs worker | 首包（SYN）可能归属 listener；首载荷时刷新为 accepted 连接的实际进程 |
| 进程在查询前退出 | 返回 `None`；未拿到 `exact` 时每秒重试，进程不存在则继续为空，不报错 |
| 系统代理 / VPN / NAT | 归属到可见的代理进程，note 标注"可能为代理转发" |
| 容器 / WSL | 宿主只能看到 `vmmem` / `wslrelay` 等宿主进程，note 标注"容器/虚拟化边界" |
| 抓镜像口 / SPAN | 本机端点不在 socket 表中，全部 `None` |
| 组播 / 广播（mDNS 5353、SSDP、NetBIOS） | 本机通常没有对应单播 socket，直接跳过，显示「—」 |
| 毫秒级短连接（DNS/UDP、CDN 短连） | socket 在两次快照之间已关闭，可能始终无法归属 |
| 系统代理 / TUN | 抓物理网卡时看到的是代理进程的连接；浏览器与代理之间是回环流量 |
| 权限不足 | 只返回可见进程；状态栏与 tooltip 标注"权限受限" |
| PID 复用 | 第一版用 TTL 缩小窗口；增强版用进程启动时间校验（Linux `starttime`、Windows `GetProcessTimes`） |
| 端口 0 / 异常端口 | 直接 `None` |

## 4. 数据来源与输入条件

### Windows

| 数据 | 来源 |
| --- | --- |
| TCP 连接与 owner PID | `GetExtendedTcpTable(AF_INET/AF_INET6, TCP_TABLE_OWNER_PID_ALL)` |
| UDP 端点与 owner PID | `GetExtendedUdpTable(AF_INET/AF_INET6, UDP_TABLE_OWNER_PID)` |
| 进程名 | `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` + `QueryFullProcessImageNameW` |

结构体：`MIB_TCPROW_OWNER_PID`、`MIB_TCP6ROW_OWNER_PID`、`MIB_UDPROW_OWNER_PID`、`MIB_UDP6ROW_OWNER_PID`。
全部通过 ctypes 声明，保持零第三方依赖。`QueryFullProcessImageNameW` 失败时只显示 PID。

### Linux

| 数据 | 来源 |
| --- | --- |
| socket 表与 inode | `/proc/net/tcp`、`tcp6`、`udp`、`udp6` |
| inode → PID | 遍历 `/proc/<pid>/fd/*`，`readlink` 得到 `socket:[inode]` |
| 进程名 | `/proc/<pid>/comm`（短名）或 `/proc/<pid>/cmdline`（完整命令行） |

可选增强：`NETLINK_SOCK_DIAG` 替代 `/proc/net`，但 inode → PID 仍需遍历 fd。

### 输入条件

- 抓包与目标进程在**同一主机**；
- Npcap 正常（Windows）或具备读取 `/proc` 的权限（Linux）；
- 会话表已归一化五元组；
- 平台限定 Windows 10/11 与 Linux；macOS 不在本期范围。

## 5. 预期输出形式

### 数据模型

```python
Session.pid: int | None
Session.process_name: str | None  # 可执行名，如 chrome.exe
Session.process_confidence: str | None  # "exact" | "port" | "ambiguous" | None
Session.process_note: str  # 归属依据或降级原因，默认空
```

`process_path`（完整路径）第一版不落库，仅在 tooltip 中按需查询，避免每会话常驻长字符串。

### 界面

| 位置 | 形式 |
| --- | --- |
| 会话面板「进程」列 | `chrome.exe (1234)`；无归属时 `—` |
| 悬停 tooltip | 进程名、PID、置信度、备注（如"仅端口匹配"/"权限受限"） |
| 状态栏 | 进程归属可用性：可用 / 权限受限 / 不支持 / 快照过期 |
| 显示过滤器 | `process.pid == 1234`、`process.name == "chrome.exe"`（大小写不敏感） |
| 详情树（增强） | 会话级节点「进程」 |
| 统计视图（增强） | 按进程的包数/字节 Top N |
| CLI（增强） | `--show-process` 在摘要后附加进程列 |

### 导出

PCAP 不承载进程信息（格式限制）；如需归档，增强版另导出 CSV/JSON：
`stream_id, pid, process_name, confidence, packets_up, packets_down, bytes`。

## 6. 与现有模块的交互

| 模块 | 改动 |
| --- | --- |
| `nps/core/process_map.py` | 新增 `SystemResolver`（平台分派）、`Snapshot`、缓存；保留 `NullResolver` 作为降级 |
| `nps/core/session.py` | `SessionTable.__init__(resolver=NullResolver())`；`add()` 在会话创建与首载荷时调用 `resolve`；`Session` 增加 3 个字段 |
| `nps/gui/session_model.py` | 进程列渲染 `name (pid)`；tooltip 增加置信度/备注 |
| `nps/gui/main_window.py` | 创建 `SystemResolver` 注入会话表；状态栏显示归属可用性；清空/停止不销毁快照 |
| `nps/filters/evaluator.py` | 新增 `process.pid` / `process.name`，字段值为 `from_session=True`，从 `session` 取 |
| `nps/gui/filter_proxy.py` | **无需改动**，已把 `session` 传入谓词 |
| `nps/core/packet.py` | **无需改动**，不把进程信息复制到每个包 |
| `scripts/probe_process.py` | 新增自检：列出本机 TCP/UDP 端点 → PID/进程名，验证 API 可用性 |
| `tests/` | 单测注入 `FakeResolver`；集成测试标记 `requires_npcap` |

设计约束：进程归属是**会话级属性**，不进入 `Packet`，避免 20 万包重复存同样的字符串。

## 7. 性能与准确性要求

| 指标 | 要求 |
| --- | --- |
| 快照构建 | Windows ≤ 30 ms / 10k 连接；Linux ≤ 100 ms / 5k socket |
| 快照刷新 | TTL 2 s；未命中强制刷新全局节流 0.5 s，不在捕获回调或每包路径 |
| 单次归属查询 | ≤ 0.05 ms（哈希查找） |
| 每会话解析次数 | 命中 `exact` 后不再查询；未命中每秒重试，直到 exact 或会话结束 |
| 内存 | 快照 ≤ 2 MB / 10k 连接；名称缓存 ≤ 1 MB |
| 对 P5 基线影响 | 解析吞吐下降 < 5%；5k pps 下队列丢弃不增长 |
| 无能/不可用时 | 立即降级为 `NullResolver`，不阻塞抓包 |

准确性口径：

- `exact` 才可表述为"该进程的连接"；
- `port` 必须标注"仅端口推断"；
- `ambiguous` 不展示进程名，只标注"端口冲突"；
- 已知代理/容器场景必须显示 note，不得静默给出错误归属。

## 8. 异常与冲突处理

| 异常 | 处理 |
| --- | --- |
| 快照读取失败（权限/API 错误） | 降级 `NullResolver`，状态栏提示一次，不刷屏 |
| 单次解析异常 | 捕获后返回 `None` 并计数；不得向 GUI 抛栈 |
| 进程名读取失败 | 保留 PID，名称显示 `—` |
| 端口冲突 | 标记 `ambiguous`，宁可不归属也不误归属 |
| 进程已退出 | `None`；重试仍失败则保持为空，不报错 |
| 快照过期 | 使用旧快照并在 tooltip 标注时间；下一次会话触发刷新 |
| 归属与 DPI 冲突 | 互不影响：`process.*` 是会话属性，`protocol` 是协议识别 |
| 会话淘汰 | 快照与名称缓存不受影响；不做反向清理 |

## 9. 验收标准

### 功能（Windows 必测，Linux 同口径）

1. 本机 `curl` / Python socket 出站 TCP，连续 10 次归属 PID 与进程名 **10/10 正确**；
2. 本机 `python -m http.server` 接受入站连接，归属到监听进程；
3. UDP DNS 查询归属到发起进程；
4. IPv6 连接归属正确；
5. 同一进程多连接（浏览器多标签）分别归属到正确 PID；
6. `process.name == "chrome.exe"` 过滤命中，大小写不敏感；
7. 端口复用：两个进程监听不同地址的同端口，按四元组区分，不误归属；
8. 进程退出后新会话不沿用旧 PID；
9. 离线 PCAP 全部为 `—`，不得误标；
10. Linux 非 root：不崩溃，只显示可见进程，note 标注"权限受限"。

### 性能

11. 10k 连接快照构建 ≤ 30 ms（Windows）；
12. 5k pps 持续 60 s，进程归属开启前后队列丢弃与 UI 帧预算无显著差异；
13. 2 万会话时进程列刷新 ≤ 100 ms（复用会话表刷新节奏）。

### 测试与文档

14. 单元测试 ≥ 15 条（四元组优先、端口回退、ambiguous、降级、缓存、PID 复用）；
15. 集成测试 ≥ 5 条，标记 `requires_npcap`，本地执行并留档；
16. 更新 `ARCHITECTURE.md`、`FILTER_SYNTAX.md`、`DEVELOPMENT.md`、`DEVLOG.md`。

## 10. 复杂度与工作量

| 工作项 | 说明 | 估算 |
| --- | --- | --- |
| Windows 表查询 | 4 个结构体 + 2 个 API + 版本/权限分支 | 0.75 天 |
| Linux `/proc` | socket 表解析、inode→PID、权限降级 | 0.75 天 |
| 快照与缓存 | TTL、线程安全、惰性刷新、异常计数 | 0.25 天 |
| 模型与会话集成 | `Session` 字段、`SessionTable` 注入、解析时机 | 0.25 天 |
| GUI 与过滤 | 进程列、tooltip、`process.*` 字段、状态栏 | 0.5 天 |
| 测试 | 单测 + 真实连接集成 + 权限矩阵 | 0.75 天 |
| 文档与演示 | 架构、过滤语法、开发说明、演示脚本 | 0.25 天 |
| **合计（双平台完整）** | | **3.5 天** |

分期口径：

- **仅 Windows 核心**（TCP/UDP + 会话列 + 单测）：约 **1.5 天**；
- **双平台核心**（不含统计/详情树）：约 **2.5 天**；
- **完整增强**（统计视图、CSV 导出、路径 tooltip）：约 **3.5–4 天**。

复杂度评级：**中高**。难点不在算法，而在跨平台 OS 接口、权限差异与归属歧义；
代码量预计 600–900 行（含测试），与 P4 的 DPI 模块量级接近。

## 11. 纳入当前计划的风险点

| 风险 | 概率 | 影响 | 缓解 |
| --- | --- | --- | --- |
| Linux 非 root 只能看到自己的进程，行为与 Windows 不一致 | 高 | 中 | 状态栏明示"权限受限"，文档写清差异 |
| 代理 / VPN / 容器导致归属到"错误的可见进程" | 高 | 中 | 强制展示置信度与 note，不表述为确定结论 |
| 端口复用导致误归属 | 中 | 中 | 四元组优先，冲突标 `ambiguous` 并放弃 |
| Windows 结构体对齐 / 32–64 位差异 | 中 | 高 | `probe_process.py` 先验证字段，再接入会话 |
| 每包查 OS 拖慢抓包 | 中 | 高 | 只允许会话创建与首载荷两次查询 + 快照缓存 |
| 进程名读取失败（系统进程/权限） | 中 | 低 | 只显示 PID，不阻塞 |
| CI 无法复现真实连接 | 高 | 中 | `FakeResolver` 覆盖规则单测，真实用例 `requires_npcap` 本地留档 |
| 排期挤占 11/24 交付窗口 | 中 | 高 | 独立分支 / P6，不进红线关键路径 |
| 用户预期"能看到对端进程" | 中 | 中 | 文档与 UI 明确"仅本机进程" |

## 12. 结论与建议

- 该功能**技术上可行**，且现有 `ProcessResolver` 接口、会话模型与过滤传参已为其留好位置，
  属于"接入成本低、边界成本高"的类型；
- 实际交付（2026-11-12）：**Windows 核心 + GUI + 过滤 + 自检 + 测试**，
  范围对应上文 1.5 天口径；Linux `/proc` 方案与统计/CSV 增强暂缓；
- 后续若要恢复 Linux：优先 `/proc/net/{tcp,udp}*` + `/proc/<pid>/fd` inode 匹配，
  需先解决非 root 权限下的可见性差异，再接入同一 `ProcessTable` 匹配层；
- 增强方向按收益排序：PID 启动时间校验（降低复用误判）→ 按进程统计/CSV →
  代理与容器场景标注 → 后台快照线程。
