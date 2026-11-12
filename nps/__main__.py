"""CLI / GUI 入口。

无参数默认启动图形界面；``--list-interfaces``、``-i``、``--offline``、``--cli``
走命令行捕获或回放。核心捕获层与解析层不依赖 Qt。
"""

from __future__ import annotations

import argparse
import sys
import time

from nps import __version__
from nps.capture.backend import CaptureConfig, CaptureStats
from nps.capture.interface import list_interfaces
from nps.capture.libpcap import DLT_NAMES, PcapError, no_device_hint
from nps.capture.libpcap import version as pcap_version
from nps.capture.pcap_backend import PcapBackend
from nps.core.buffer import BoundedPacketQueue
from nps.core.packet import Packet

ETHERTYPES: dict[int, str] = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "VLAN",
}


def network_hint(packet: Packet) -> str:
    """只做"这一帧是 IPv4 / IPv6 / ARP"的粗判，完整解析在 P1 的 decode 层。"""
    raw = packet.raw
    if packet.linktype == 1:  # DLT_EN10MB
        if len(raw) < 14:
            return "-"
        ethertype = int.from_bytes(raw[12:14], "big")
        if ethertype in ETHERTYPES:
            return ETHERTYPES[ethertype]
        return f"0x{ethertype:04x}"
    if packet.linktype == 0:  # DLT_NULL：4 字节地址族，主机字节序
        if len(raw) < 4:
            return "-"
        family = int.from_bytes(raw[:4], sys.byteorder)
        if family == 2:  # AF_INET
            return "IPv4"
        if family in (23, 24, 28, 30):  # AF_INET6 的各平台取值
            return "IPv6"
        return f"AF {family}"

    offset = packet.network_offset
    if offset is None or len(raw) <= offset:
        return "-"
    version = raw[offset] >> 4
    if version == 4:
        return "IPv4"
    if version == 6:
        return "IPv6"
    return f"0x{version:x}"


def format_packet(packet: Packet, verbose: bool = False) -> str:
    line = (
        f"{packet.index:>6} {packet.ts_text} {network_hint(packet):<6} "
        f"{packet.caplen:>5}/{packet.wirelen:<5}"
    )
    if verbose:
        line += f" {packet.head_hex()}"
    return line


def print_interfaces() -> int:
    try:
        devices = list_interfaces()
        version = pcap_version()
    except PcapError as exc:
        print(f"错误：{exc}", file=sys.stderr)
        return 1

    print(f"libpcap: {version}")
    if not devices:
        print(f"错误：{no_device_hint()}", file=sys.stderr)
        return 1
    print(f"共 {len(devices)} 个设备：")
    for index, device in enumerate(devices, 1):
        promisc = "支持混杂" if device.promisc_supported else "不支持混杂"
        print(f"{index:>2}. {device.label}  [{promisc}]")
    return 0


def _print_open_notes(backend: PcapBackend) -> None:
    if backend.warning:
        print(f"提示（pcap_activate 告警）：{backend.warning}", file=sys.stderr)
    for note in backend.notes:
        print(f"提示：{note}", file=sys.stderr)
    print(f"链路类型：{DLT_NAMES.get(backend.datalink(), backend.datalink())}")


def print_summary(printed: int, stats: CaptureStats, offline: bool = False) -> None:
    print("--- 统计 ---")
    print(f"{'已读取包数' if offline else '已显示包数'}        : {printed}")
    print(f"驱动交包(ps_recv) : {stats.recv}")
    print(f"内核缓冲丢弃      : {stats.drop}")
    print(f"接口丢弃          : {stats.ifdrop}")
    print(f"队列丢弃          : {stats.queue_dropped}")


def run_capture(args: argparse.Namespace) -> int:
    queue = BoundedPacketQueue(args.queue_size)
    backend = PcapBackend()
    try:
        if args.offline:
            backend.open_offline(args.offline)
        else:
            backend.open(
                CaptureConfig(
                    device=args.interface,
                    snaplen=args.snaplen,
                    promisc=not args.no_promisc,
                    timeout_ms=args.timeout,
                    buffer_size=args.buffer_size,
                )
            )
        if args.filter:
            backend.set_filter(args.filter)
        backend.start(queue.put)
    except PcapError as exc:
        backend.close()
        print(f"错误：{exc}", file=sys.stderr)
        return 1

    _print_open_notes(backend)
    if args.offline:
        print(f"离线文件：{args.offline}")
    if args.filter:
        print(f"捕获过滤器：{args.filter}")
    if not args.count and not args.duration:
        print("未指定 --count/--duration，按 Ctrl+C 结束。")

    printed = 0
    interrupted = False
    started = time.monotonic()
    try:
        while True:
            if args.duration and time.monotonic() - started >= args.duration:
                break
            batch = queue.drain(500)
            if not batch:
                if backend.is_offline and not backend.is_running:
                    break  # 离线文件已读到 EOF
                time.sleep(0.01)
                continue
            for packet in batch:
                print(format_packet(packet, args.verbose))
                printed += 1
                if args.count and printed >= args.count:
                    break
            if args.count and printed >= args.count:
                break
    except KeyboardInterrupt:
        interrupted = True
        print("\n已中断。", file=sys.stderr)
    finally:
        offline = backend.is_offline
        stats = backend.stats() if backend.is_open else CaptureStats()
        stats.queue_dropped = queue.dropped
        backend.close()
        if backend.last_error:
            print(f"警告：捕获线程异常退出：{backend.last_error}", file=sys.stderr)
        print_summary(printed, stats, offline)

    return 130 if interrupted else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nps",
        description="NPS：基于 libpcap/Npcap 的轻量网络嗅探器（仅限授权环境）",
    )
    parser.add_argument("--version", action="store_true", help="打印版本后退出")
    parser.add_argument("--list-interfaces", action="store_true", help="列出可用网卡")
    parser.add_argument("-i", "--interface", help="网卡名（Windows 形如 \\Device\\NPF_{GUID}）")
    parser.add_argument("--offline", metavar="PATH", help="读取离线 PCAP 文件而不是抓包")
    parser.add_argument("-f", "--filter", help="BPF 捕获过滤器，如 'tcp port 80'")
    parser.add_argument("-c", "--count", type=int, default=0, help="显示到 N 个包后停止")
    parser.add_argument("--duration", type=float, default=0.0, help="抓取 N 秒后停止")
    parser.add_argument("--snaplen", type=int, default=65535, help="每个包捕获的字节数")
    parser.add_argument("--timeout", type=int, default=100, help="读超时（毫秒），影响停止时延")
    parser.add_argument("--buffer-size", type=int, default=8 * 1024 * 1024, help="内核缓冲字节数")
    parser.add_argument("--queue-size", type=int, default=100_000, help="用户态队列容量")
    parser.add_argument("--no-promisc", action="store_true", help="不开启混杂模式")
    parser.add_argument("-v", "--verbose", action="store_true", help="附加前若干字节的十六进制")
    parser.add_argument("--cli", action="store_true", help="强制命令行模式（需要 -i 或 --offline）")
    parser.add_argument("--gui", action="store_true", help="启动图形界面（默认行为）")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.version:
        print(f"nps {__version__}")
        try:
            print(f"libpcap {pcap_version()}")
        except PcapError as exc:
            print(f"libpcap 不可用：{exc}", file=sys.stderr)
        return 0

    if args.list_interfaces:
        return print_interfaces()

    if args.offline and args.interface:
        print("错误：--offline 与 -i 不能同时使用。", file=sys.stderr)
        return 2
    if args.cli and not (args.interface or args.offline):
        print("错误：--cli 模式需要 -i 或 --offline。", file=sys.stderr)
        return 2
    if args.count < 0:
        print("错误：--count 不能为负数。", file=sys.stderr)
        return 2
    if args.duration < 0:
        print("错误：--duration 不能为负数。", file=sys.stderr)
        return 2

    if args.interface or args.offline:
        return run_capture(args)

    # 无参数（或 --gui）：启动图形界面
    from nps.gui import run_gui

    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
