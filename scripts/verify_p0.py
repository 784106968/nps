"""P0 验收数据采集。

产物是一张可直接贴进报告/PR 的表格，覆盖 P0 的三条硬指标：

1. BPF 过滤器是否真的只放行匹配流量（逐包校验 IP 协议号）；
2. 开始 → 停止的时延是否 ≤ 500 ms（重复 20 次取分布）；
3. 驱动统计与队列丢弃是否可见。

    python scripts/verify_p0.py                 # 默认用回环设备
    python scripts/verify_p0.py -i "<设备名>"    # 指定设备

退出码：0 全部通过；1 有检查项失败。
"""

from __future__ import annotations

import argparse
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nps.capture.backend import CaptureConfig, CaptureStats  # noqa: E402
from nps.capture.interface import Interface, choose_default, list_interfaces  # noqa: E402
from nps.capture.libpcap import PcapError  # noqa: E402
from nps.capture.pcap_backend import PcapBackend  # noqa: E402
from nps.core.buffer import BoundedPacketQueue  # noqa: E402
from nps.core.packet import Packet  # noqa: E402

LOOPBACK_UDP_PORT = 9999
STOP_ROUNDS = 20
STOP_BUDGET_MS = 500.0


@dataclass
class Window:
    packets: list[Packet]
    stats: CaptureStats


def ip_protocol(packet: Packet) -> int | None:
    """取 IPv4 头里的协议号；非 IPv4 或长度不足返回 None。"""
    offset = packet.network_offset
    raw = packet.raw
    if offset is None or len(raw) <= offset + 9:
        return None
    if raw[offset] >> 4 != 4:  # 只看 IPv4
        return None
    return int(raw[offset + 9])


def pick_device(devices: list[Interface], wanted: str | None) -> Interface:
    if wanted:
        for device in devices:
            if device.name == wanted:
                return device
        raise SystemExit(f"未找到设备：{wanted}")
    for device in devices:
        if device.is_loopback:
            return device
    return choose_default(devices)


def udp_burst(count: int = 300) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for index in range(count):
            sock.sendto(f"nps-verify-{index:04d}".encode(), ("127.0.0.1", LOOPBACK_UDP_PORT))
            if index % 50 == 0:
                time.sleep(0.005)


def icmp_burst() -> bool:
    """触发 ICMP 回环流量；ping 不可用时返回 False。"""
    args = (
        ["ping", "-n", "4", "127.0.0.1"]
        if sys.platform == "win32"
        else [
            "ping",
            "-c",
            "4",
            "127.0.0.1",
        ]
    )
    try:
        result = subprocess.run(
            args,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return result.returncode == 0


def capture_window(
    device: str,
    expression: str | None,
    seconds: float,
    trigger,
) -> tuple[Window, object]:
    """在给定过滤器下抓一段时间，同时执行触发动作。"""
    backend = PcapBackend()
    queue = BoundedPacketQueue(100_000)
    backend.open(CaptureConfig(device=device, promisc=False, timeout_ms=100))
    trigger_result = None
    try:
        if expression:
            backend.set_filter(expression)
        backend.start(queue.put)
        time.sleep(0.2)
        trigger_result = trigger()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            time.sleep(0.02)
        stats = backend.stats()
    finally:
        backend.stop()
        backend.close()
    return Window(queue.drain(100_000), stats), trigger_result


def measure_stop_latency(device: str) -> list[float]:
    latencies: list[float] = []
    for _ in range(STOP_ROUNDS):
        backend = PcapBackend()
        backend.open(CaptureConfig(device=device, promisc=False, timeout_ms=100))
        backend.start(lambda packet: None)
        time.sleep(0.05)
        started = time.perf_counter()
        backend.stop()
        latencies.append((time.perf_counter() - started) * 1000)
        backend.close()
    return latencies


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="P0 验收数据采集")
    parser.add_argument("-i", "--interface", help="指定设备，缺省选回环")
    args = parser.parse_args(argv)

    devices = list_interfaces()
    if not devices:
        print("错误：没有可用设备，请先安装 Npcap/libpcap")
        return 1
    target = pick_device(devices, args.interface)
    print(f"设备：{target.name}")
    print(f"描述：{target.description or '(无)'}  loopback={target.is_loopback}")
    print(f"设备总数：{len(devices)}")
    print("-" * 72)

    failures: list[str] = []

    # 1. 过滤器：udp
    window, _ = capture_window(target.name, "udp", 2.0, udp_burst)
    protos = [ip_protocol(packet) for packet in window.packets]
    udp_count = sum(1 for proto in protos if proto == 17)
    udp_only = all(proto == 17 for proto in protos if proto is not None)
    print(
        f"[1] filter='udp'      捕获 {len(window.packets):>4} 包，"
        f"UDP {udp_count:>4} 包，全部为 UDP={udp_only}"
    )
    if udp_count == 0:
        failures.append("udp 过滤器没有捕获到 UDP 包")
    elif not udp_only:
        failures.append("udp 过滤器混入了非 UDP 包")

    # 2. 过滤器：icmp
    icmp_window, ping_ok = capture_window(target.name, "icmp", 2.5, icmp_burst)
    icmp_protos = [ip_protocol(packet) for packet in icmp_window.packets]
    icmp_count = sum(1 for proto in icmp_protos if proto == 1)
    icmp_only = all(proto == 1 for proto in icmp_protos if proto is not None)
    print(
        f"[2] filter='icmp'     捕获 {len(icmp_window.packets):>4} 包，"
        f"ICMP {icmp_count:>4} 包，全部为 ICMP={icmp_only}，ping可用={bool(ping_ok)}"
    )
    if not ping_ok:
        print("    [i] ping 不可用，跳过 ICMP 断言")
    elif icmp_count == 0:
        failures.append("icmp 过滤器没有捕获到 ICMP 包")
    elif not icmp_only:
        failures.append("icmp 过滤器混入了非 ICMP 包")

    # 3. 过滤器：tcp port 80（只发 UDP，应当一个都收不到）
    tcp_window, _ = capture_window(target.name, "tcp port 80", 1.5, udp_burst)
    print(f"[3] filter='tcp port 80'  捕获 {len(tcp_window.packets):>4} 包（期望 0）")
    if tcp_window.packets:
        failures.append("tcp port 80 过滤器放行了非 80 流量")

    # 4. 非法表达式错误透传
    backend = PcapBackend()
    backend.open(CaptureConfig(device=target.name, promisc=False, timeout_ms=100))
    try:
        backend.set_filter("tcp por 80")
    except PcapError as exc:
        print(f"[4] 非法过滤器          按预期报错：{exc}")
    else:
        failures.append("非法过滤器未报错")
    finally:
        backend.close()

    # 5. 停止时延
    latencies = measure_stop_latency(target.name)
    p95 = statistics.quantiles(latencies, n=20)[-1] if len(latencies) > 1 else latencies[0]
    print(
        f"[5] 停止时延 x{STOP_ROUNDS}      "
        f"min={min(latencies):.1f}ms  中位={statistics.median(latencies):.1f}ms  "
        f"p95={p95:.1f}ms  max={max(latencies):.1f}ms"
    )
    if max(latencies) > STOP_BUDGET_MS:
        failures.append(f"停止时延超过 {STOP_BUDGET_MS:.0f}ms")

    # 6. 高负载丢包统计
    load_window, _ = capture_window(target.name, "udp", 2.0, lambda: udp_burst(2000))
    print(
        f"[6] 负载 2000 包         捕获 {len(load_window.packets):>4} 包，"
        f"ps_recv={load_window.stats.recv} ps_drop={load_window.stats.drop} "
        f"ps_ifdrop={load_window.stats.ifdrop}"
    )

    # 7. 线程泄漏检查
    before = threading.active_count()
    for _ in range(5):
        backend = PcapBackend()
        backend.open(CaptureConfig(device=target.name, promisc=False, timeout_ms=100))
        backend.start(lambda packet: None)
        backend.stop()
        backend.close()
    after = threading.active_count()
    print(f"[7] 线程数               before={before} after={after}")
    if after > before:
        failures.append("疑似线程泄漏")

    print("-" * 72)
    if failures:
        for item in failures:
            print(f"[x] {item}")
        return 1
    print("结论：P0 在线验收项全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
