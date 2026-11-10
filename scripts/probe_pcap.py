"""ctypes 捕获层冒烟探针。

用途：在写任何界面之前，先证明"库能加载、设备能枚举、句柄能激活、
过滤器能编译、包能取到、能停下来"。

     python scripts/probe_pcap.py                # 自动选网卡，最多等 3 秒
     python scripts/probe_pcap.py -i "<设备名>" -f "icmp" --wait 5

退出码：0 表示全部 API 步骤通过（没有流量也算通过）；1 表示失败。
"""

from __future__ import annotations

import argparse
import platform
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from nps import __version__  # noqa: E402
from nps.capture.backend import CaptureConfig  # noqa: E402
from nps.capture.interface import choose_default, list_interfaces  # noqa: E402
from nps.capture.libpcap import DLT_NAMES, PcapError, no_device_hint  # noqa: E402
from nps.capture.libpcap import version as pcap_version
from nps.capture.pcap_backend import PcapBackend  # noqa: E402

INVALID_FILTER = "tcp por 80"  # 故意写错，验证错误透传


def step(text: str) -> None:
    print(f"[.] {text}")


def ok(text: str) -> None:
    print(f"[+] {text}")


def fail(text: str) -> None:
    print(f"[x] {text}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="NPS 捕获层冒烟探针")
    parser.add_argument("-i", "--interface", help="指定网卡，缺省自动选择")
    parser.add_argument("-f", "--filter", default="", help="BPF 过滤器（可选）")
    parser.add_argument("--wait", type=float, default=3.0, help="等待首个包的秒数")
    args = parser.parse_args(argv)

    print("=" * 68)
    print(f"NPS probe  v{__version__}")
    print(f"python {platform.python_version()} / {platform.platform()}")
    print("=" * 68)

    step("加载 libpcap / Npcap")
    try:
        version = pcap_version()
    except PcapError as exc:
        fail(str(exc))
        return 1
    ok(f"libpcap {version}")

    step("枚举设备")
    try:
        devices = list_interfaces()
    except PcapError as exc:
        fail(f"枚举失败：{exc}")
        return 1
    if not devices:
        fail(no_device_hint())
        return 1
    for index, device in enumerate(devices, 1):
        flag = "回环" if device.is_loopback else "    "
        print(f"    {index:>2}. [{flag}] {device.name}  {device.description}")
    ok(f"共 {len(devices)} 个设备")

    step("选择设备")
    try:
        target = devices[0]
        if args.interface:
            matches = [d for d in devices if d.name == args.interface]
            if not matches:
                fail(f"未找到设备：{args.interface}")
                return 1
            target = matches[0]
        else:
            target = choose_default(devices)
    except PcapError as exc:
        fail(str(exc))
        return 1
    ok(f"使用 {target.name}")

    backend = PcapBackend()
    try:
        step("pcap_create -> pcap_set_* -> pcap_activate")
        backend.open(
            CaptureConfig(
                device=target.name,
                promisc=not target.is_loopback,
                timeout_ms=100,
            )
        )
        ok(f"激活成功，datalink={DLT_NAMES.get(backend.datalink(), backend.datalink())}")
        for note in backend.notes:
            print(f"    提示：{note}")
        if backend.warning:
            print(f"    告警：{backend.warning}")

        step("非法过滤器错误透传")
        try:
            backend.set_filter(INVALID_FILTER)
        except PcapError as exc:
            ok(f"按预期失败：{exc}")
        else:
            fail("非法过滤器竟然编译通过，错误处理可能有问题")
            return 1

        if args.filter:
            step(f"编译过滤器：{args.filter}")
            backend.set_filter(args.filter)
            ok("过滤器已生效")

        step(f"抓包（最多等待 {args.wait:g} 秒）")
        received = []

        def on_packet(packet):
            if len(received) < 3:
                received.append(packet)

        backend.start(on_packet)
        deadline = time.monotonic() + args.wait
        while time.monotonic() < deadline and not received:
            time.sleep(0.05)

        step("统计")
        stats = backend.stats()
        print(
            f"    ps_recv={stats.recv} ps_drop={stats.drop} "
            f"ps_ifdrop={stats.ifdrop} callback_errors={backend.callback_errors}"
        )

        step("pcap_breakloop + stop 时延")
        started = time.perf_counter()
        backend.stop()
        elapsed = (time.perf_counter() - started) * 1000
        ok(f"停止耗时 {elapsed:.1f} ms")
        if elapsed > 500:
            fail("停止时延超过 500 ms，请检查 timeout 设置")
            return 1

        if received:
            first = received[0]
            ok(f"捕获到 {len(received)} 个包，首个 caplen={first.caplen} wirelen={first.wirelen}")
            print(f"    前 16 字节：{first.head_hex(16)}")
        else:
            print("[i] 等待期内没有流量（回环/空闲网卡属正常，不算失败）")

        if backend.last_error:
            fail(f"捕获线程异常：{backend.last_error}")
            return 1
    except PcapError as exc:
        fail(str(exc))
        return 1
    finally:
        backend.close()

    print("=" * 68)
    print("结论：捕获层 API 全部通过")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
