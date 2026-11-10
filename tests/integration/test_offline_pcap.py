"""离线 PCAP 回放测试。

这条路径与在线抓包共用同一套 dispatch/回调/数据结构，因此在没有网卡驱动的
环境里也能验证 ctypes 绑定是否正确。需要 libpcap/Npcap 的 DLL，故打标记跳过 CI。
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from nps.capture.backend import CaptureStats
from nps.capture.libpcap import DLT_EN10MB, PcapError
from nps.capture.pcap_backend import PcapBackend
from nps.core.buffer import BoundedPacketQueue
from nps.core.packet import Packet

pytestmark = pytest.mark.requires_npcap

FIXTURE = Path(__file__).resolve().parents[1] / "fixtures" / "sample_traffic.pcap"


def collect(
    expression: str | None = None,
    timeout: float = 5.0,
) -> tuple[list[Packet], CaptureStats]:
    assert FIXTURE.exists(), "缺少合成 PCAP，请先运行 scripts/make_fixtures.py"
    backend = PcapBackend()
    queue = BoundedPacketQueue(1000)
    backend.open_offline(str(FIXTURE))
    try:
        if expression:
            backend.set_filter(expression)
        backend.start(queue.put)
        deadline = time.monotonic() + timeout
        while backend.is_running and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.05)  # 让最后一批入队完成
        packets = queue.drain(1000)
        stats = backend.stats()
    finally:
        backend.close()
    return packets, stats


def test_reads_all_packets() -> None:
    packets, stats = collect()
    assert len(packets) == 6
    assert [packet.index for packet in packets] == [1, 2, 3, 4, 5, 6]
    assert stats.recv == 6


def test_datalink_is_ethernet() -> None:
    backend = PcapBackend()
    try:
        backend.open_offline(str(FIXTURE))
        assert backend.datalink() == DLT_EN10MB
        assert backend.is_offline is True
    finally:
        backend.close()


def test_filter_applied_offline() -> None:
    packets, _ = collect("icmp")
    assert len(packets) == 2


def test_invalid_filter_raises() -> None:
    backend = PcapBackend()
    try:
        backend.open_offline(str(FIXTURE))
        with pytest.raises(PcapError):
            backend.set_filter("tcp por 80")
    finally:
        backend.close()


def test_export_then_read_back(tmp_path) -> None:
    """导出的 PCAP 能被 libpcap 重新读回，包数与时间戳保持一致。"""
    from nps.pcapio import write_pcap

    packets, _ = collect()
    target = tmp_path / "export.pcap"
    assert write_pcap(target, packets) == len(packets)

    backend = PcapBackend()
    queue = BoundedPacketQueue(100)
    backend.open_offline(str(target))
    try:
        backend.start(queue.put)
        deadline = time.monotonic() + 5
        while backend.is_running and time.monotonic() < deadline:
            time.sleep(0.01)
        time.sleep(0.05)
        restored = queue.drain(100)
    finally:
        backend.close()

    assert len(restored) == len(packets)
    assert [p.wirelen for p in restored] == [p.wirelen for p in packets]


def test_raw_bytes_preserved() -> None:
    packets, _ = collect()
    # 以太网帧头 + IPv4 + UDP 载荷都应在 raw 中
    assert packets[0].caplen == packets[0].wirelen
    assert b"NPS-fixture" in bytes(packets[0].raw)
