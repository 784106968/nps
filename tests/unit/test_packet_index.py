"""包序号必须跨后端实例单调，避免停止/重启后解析缓存串包。"""

from __future__ import annotations

from nps.capture.pcap_backend import PcapBackend


def test_next_index_is_monotonic_across_instances() -> None:
    first = PcapBackend._next_index()
    second = PcapBackend._next_index()

    assert second == first + 1


def test_backends_share_the_process_wide_sequence() -> None:
    before = PcapBackend._next_index()
    backend = PcapBackend()

    assert backend._next_index() > before
