# 开发环境与故障排查

## 1. 环境准备

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\Activate.ps1
pip install -e ".[dev]"            # 开发工具（pytest / ruff / coverage）
pip install -e ".[gui]"            # P1 起需要 GUI 时再装
```

核心无第三方依赖：libpcap 通过 `ctypes` 直接调用。

### Windows

1. 安装 [Npcap](https://npcap.com/)，安装时勾选 **Support loopback traffic**；
2. 无需勾选 "WinPcap API-compatible mode"；
3. 若安装时选择了"限制为管理员"，需以管理员身份运行终端；
4. **不要**把 `wpcap.dll` 复制进项目或打包产物（再分发需 OEM 授权）。

### Linux

```bash
sudo apt-get install -y libpcap0.8        # 运行库
sudo setcap cap_net_raw,cap_net_admin=eip $(readlink -f $(which python3))
```

`CAP_NET_ADMIN` 用于设置混杂模式，只有 `CAP_NET_RAW` 时能在普通模式抓包但无法开混杂。

## 2. 常用命令

```bash
python -m nps --list-interfaces                  # 设备列表
python -m nps -i "<设备>" -f "tcp port 80" -c 20 # 抓 20 个包
python -m nps -i "<设备>" --duration 5           # 抓 5 秒
python -m nps --offline tests/fixtures/sample_traffic.pcap
python scripts/probe_pcap.py                     # 底层 API 冒烟
python scripts/probe_process.py                  # 进程归属自检（Windows）
python scripts/make_fixtures.py                  # 重新生成合成 PCAP
pytest -m "not requires_npcap"                   # CI 口径
pytest -m requires_npcap                         # 真实网卡
ruff check . && ruff format --check .
```

## 3. 故障排查

| 现象 | 常见原因 | 处理 |
| --- | --- | --- |
| `--list-interfaces` 返回 0 个设备 | 只有 `wpcap.dll` 没有驱动服务；或 Npcap 未安装 | 安装 Npcap；确认 `sc query npcap` 有输出 |
| 版本号显示 `WinPcap version 4.1.3 ... 2009` | 加载到了 2010 年的旧 DLL | 装 Npcap；本项目已优先查找 `System32\Npcap\wpcap.dll` |
| `pcap_activate` 返回 `-8 权限不足` | 未以管理员/root 运行 | 提升权限或重新 `setcap` |
| 过滤器报"编译失败" | 表达式语法错误 | 错误信息来自 `pcap_geterr`，原文即原因 |
| `ps_drop` 持续增长 | 内核缓冲过小或用户态消费太慢 | 调大 `--buffer-size`，减小解析开销 |
| 队列丢弃 > 0 | GUI/CLI 消费跟不上 | 降低刷新批量、提高消费频率、减小 snaplen |
| 回环抓不到包 | Npcap 安装时未勾选 loopback | 重装 Npcap 并勾选该项 |
| 回环包解析不出 IP | 回环设备是 `DLT_NULL`，不能用 14 字节以太网头 | 按 `packet.network_offset` 取偏移（Npcap 回环为 4） |
| 安装报 `silent installation is only supported in Npcap OEM` | 免费版不支持 `/S` 静默安装 | 用图形向导安装，勾选 loopback；静默仅 OEM 版可用 |
| Npcap 安装器无提示直接退出（退出码 2） | 系统残留旧 WinPcap 注册项或 `System32\wpcap.dll` | 卸载 WinPcap，并把残留 `wpcap.dll`/`packet.dll` 移出 System32 后重试 |
| 无线网卡抓不到其它主机 | 混杂模式 ≠ 监控模式 | 属预期行为，见 `CONCEPTS.md` §5 |
| 会话「进程」列一直是「—」 | 非 Windows、离线回放或归属失败 | 运行 `python scripts/probe_process.py` 看状态；离线 PCAP 无归属属预期 |
| 进程列只有 PID、没有名称 | `OpenProcess` 权限不足或进程已退出 | 提升权限重试；PID 仍可作线索 |
| 停止按钮响应慢 | `timeout` 设置过大 | 保持 100 ms，最多 500 ms 内退出 |

## 4. 无驱动环境下的开发

没有安装抓包驱动时，仍可开发与测试：

- `FakeBackend`：内存投喂包，驱动 `回调 → 队列 → 消费` 全链路（CI 使用）；
- 离线 PCAP：`python -m nps --offline <file>`，与在线抓包共用同一套 `pcap_dispatch` 回调；
- 合成数据：`scripts/make_fixtures.py` 生成 UDP/ICMP 混合流量，**禁止提交真实抓包**。

## 5. 提交前检查

```bash
ruff check . && ruff format --check .
pytest -m "not requires_npcap"
```

真实网卡相关改动，另在本地执行 `pytest -m requires_npcap` 并把输出贴到 PR。
