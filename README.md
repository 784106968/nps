# NPS — Network Packet Sniffer

面向授权网络诊断、教学研究与自有系统测试的轻量网络嗅探器。
捕获层通过 **ctypes 直连 libpcap / Npcap 新 API**，不依赖任何第三方 Python 绑定。

> **合法使用声明**
> 使用本工具捕获网络流量，必须获得网络所有者、系统管理员或相关数据主体的明确授权。
> 未经授权截取、存储、分析或传播网络通信内容，在许多司法辖区可能承担法律责任。
> 本项目不提供规避授权、隐蔽监听、TLS 解密或攻击性能力。

## 当前状态

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| P0 | 仓库基线、ctypes 捕获内核、设备枚举、BPF、统计、停止机制 | **完成**（在线验收全过） |
| P1 | Wireshark 风格三窗格 GUI、7 种协议解析、十六进制联动、PCAP 导出 | **完成**（实时落盘顺延 P3） |
| P2 | 显示过滤（`ip.src`、`tcp.port`、`icmp.type`、`protocol`、逻辑运算、CIDR） | **完成**（HTTP 语义过滤待 P4 DPI） |
| P3 | 会话表与流追踪（五元组合并、老化、同流高亮、会话面板） | **完成**（进程归属待后续） |
| P4 | DPI 协议识别（HTTP/TLS/SSH/DNS/BitTorrent）、TLS 握手解析（SNI/ALPN）、字段复制、统计视图 | **完成** |
| P5 | 流时序图、性能基线 | 未开始 |

完整计划、验收标准与日程见 [`NPS-Readme.md`](NPS-Readme.md)，逐日记录见
[`docs/DEVLOG.md`](docs/DEVLOG.md)。

> P0 验收数据（Npcap 1.90 / Windows 10）：12 个设备、过滤器 `udp` 300/300、`icmp` 8/8、
> `tcp port 80` 0 包、停止时延 max 0.5 ms、2000 包负载 `ps_drop=0`、59 条测试全过。
> 采集脚本：`python scripts/verify_p0.py`。

## 安装

核心无第三方依赖：

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

Windows 需先安装 [Npcap](https://npcap.com/)（勾选 "Support loopback traffic"）。
本项目**不随包分发** Npcap 的 DLL 或驱动。

## 快速开始

```bash
# 启动图形界面（三窗格：包列表 / 协议详情 / 十六进制）
python -m nps

# 查看 libpcap 版本与可用网卡
python -m nps --list-interfaces

# 抓取 20 个 80 端口包并打印摘要
python -m nps -i "<设备名>" -f "tcp port 80" -c 20

# 界面第二行是「显示过滤器」，支持逻辑运算与 CIDR，例如：
#   ip.src == 10.0.0.5 && tcp.port == 443
#   ip.addr == 192.168.0.0/16 && !(protocol == arp)
# 语法见 docs/FILTER_SYNTAX.md

# 抓 5 秒后自动停止并输出统计
python -m nps -i "<设备名>" --duration 5

# 底层 API 冒烟探针（装载、创建、激活、编译过滤器、统计、停止时延）
python scripts/probe_pcap.py
```

### Windows 快捷启动

双击 **`scripts\run_gui.cmd`** 即可启动（不会留下控制台窗口）。也可以做成桌面快捷方式：

```powershell
$ws = New-Object -ComObject WScript.Shell
$sc = $ws.CreateShortcut("$env:USERPROFILE\Desktop\NPS Sniffer.lnk")
$sc.TargetPath = "$PWD\.venv\Scripts\pythonw.exe"
$sc.Arguments = "-m nps"
$sc.WorkingDirectory = "$PWD"
$sc.Description = "NPS 网络嗅探器"
$sc.Save()
```

Linux 需要 `CAP_NET_RAW` 与 `CAP_NET_ADMIN`：

```bash
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

## 目录结构

```text
nps/
├── capture/     ctypes 绑定、捕获后端、设备枚举
├── core/        包模型、有界队列、统计
└── __main__.py  命令行入口
docs/            架构、概念、开发与过滤语法文档
scripts/         probe_pcap.py 等辅助脚本
tests/           单元测试与合成 PCAP
```

## 文档

- [`NPS-Readme.md`](NPS-Readme.md)：开发计划、阶段验收、风险与降级预案
- [`docs/CONCEPTS.md`](docs/CONCEPTS.md)：OSI 分层、抓包点与加密边界
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)：分层职责与数据流
- [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)：环境、权限与故障排查
- [`docs/DEVLOG.md`](docs/DEVLOG.md)：每日开发记录

## 许可证

MIT，详见 [`LICENSE`](LICENSE)。
