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
