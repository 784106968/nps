"""CLI 参数与摘要格式测试。"""

from __future__ import annotations

from nps.__main__ import format_packet, main, network_hint
from nps.core.packet import Packet


def make_ethernet_packet(raw: bytes, index: int = 1) -> Packet:
    return Packet(
        index=index,
        ts=1_700_000_000.0,
        caplen=len(raw),
        wirelen=len(raw),
        linktype=1,
        raw=memoryview(raw),
    )


def ipv4_frame() -> bytes:
    return b"\x00" * 12 + b"\x08\x00" + b"\x45" + b"\x00" * 10


def test_network_hint_ipv4() -> None:
    assert network_hint(make_ethernet_packet(ipv4_frame())) == "IPv4"


def test_network_hint_arp() -> None:
    frame = b"\x00" * 12 + b"\x08\x06" + b"\x00" * 10
    assert network_hint(make_ethernet_packet(frame)) == "ARP"


def test_network_hint_unknown_link_type() -> None:
    packet = Packet(
        index=1,
        ts=0.0,
        caplen=4,
        wirelen=4,
        linktype=999,
        raw=memoryview(b"\x00\x01\x02\x03"),
    )
    assert network_hint(packet) == "-"


def test_network_hint_truncated_frame() -> None:
    assert network_hint(make_ethernet_packet(b"\x00\x01")) == "-"


def test_format_packet_contains_key_fields() -> None:
    line = format_packet(make_ethernet_packet(ipv4_frame(), index=7), verbose=True)
    assert "7" in line
    assert "IPv4" in line
    assert "/" in line


def test_version_exits_zero(capsys) -> None:
    assert main(["--version"]) == 0
    assert "nps 0.1.0" in capsys.readouterr().out


def test_missing_interface_returns_usage_error(capsys) -> None:
    assert main([]) == 2
    assert "list-interfaces" in capsys.readouterr().err


def test_negative_count_rejected(capsys) -> None:
    assert main(["-i", "fake0", "--count", "-1"]) == 2
    assert "count" in capsys.readouterr().err


def test_negative_duration_rejected(capsys) -> None:
    assert main(["-i", "fake0", "--duration", "-1"]) == 2
    assert "duration" in capsys.readouterr().err
