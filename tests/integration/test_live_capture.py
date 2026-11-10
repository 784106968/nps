"""需要真实网卡与抓包驱动的集成测试。

CI 无抓包驱动，默认跳过；本地用 ``pytest -m requires_npcap`` 执行。
若本机只装了 wpcap.dll 而没有驱动服务，会以 skip 说明原因，而不是伪装成通过。
"""

from __future__ import annotations

import socket
import time

import pytest

from nps.capture.backend import CaptureConfig
from nps.capture.interface import Interface, list_interfaces
from nps.capture.libpcap import PcapError, no_device_hint
from nps.capture.pcap_backend import PcapBackend
from nps.core.buffer import BoundedPacketQueue

pytestmark = pytest.mark.requires_npcap


def require_devices() -> list[Interface]:
    try:
        devices = list_interfaces()
    except PcapError as exc:
        pytest.skip(f"libpcap 不可用：{exc}")
    if not devices:
        pytest.skip(no_device_hint())
    return devices


def test_list_interfaces_returns_devices() -> None:
    devices = require_devices()
    assert all(device.name for device in devices)


def test_invalid_filter_reports_libpcap_error() -> None:
    devices = require_devices()
    backend = PcapBackend()
    try:
        backend.open(CaptureConfig(device=devices[0].name, promisc=False))
        with pytest.raises(PcapError) as excinfo:
            backend.set_filter("tcp por 80")
        assert "编译失败" in str(excinfo.value)
    finally:
        backend.close()


def test_stop_latency_under_500ms() -> None:
    devices = require_devices()
    backend = PcapBackend()
    try:
        backend.open(CaptureConfig(device=devices[0].name, promisc=False, timeout_ms=100))
        backend.start(lambda packet: None)
        time.sleep(0.2)
        started = time.perf_counter()
        backend.stop()
        elapsed = (time.perf_counter() - started) * 1000
        assert elapsed < 500, f"停止耗时 {elapsed:.1f} ms"
    finally:
        backend.close()


def test_loopback_capture_sees_udp() -> None:
    loopbacks = [device for device in require_devices() if device.is_loopback]
    if not loopbacks:
        pytest.skip("未安装回环适配器（Npcap 安装时需勾选 loopback 支持）")

    backend = PcapBackend()
    queue = BoundedPacketQueue(1000)
    try:
        backend.open(CaptureConfig(device=loopbacks[0].name, promisc=False, timeout_ms=100))
        backend.set_filter("udp")
        backend.start(queue.put)

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for _ in range(5):
                sock.sendto(b"nps-probe", ("127.0.0.1", 9999))
                time.sleep(0.1)

        deadline = time.monotonic() + 3.0
        received = queue.drain(100)
        while not received and time.monotonic() < deadline:
            time.sleep(0.1)
            received = queue.drain(100)
        assert received, "回环抓包未收到任何 UDP 包"
    finally:
        backend.close()
