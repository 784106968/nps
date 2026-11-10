"""分层解析测试。

报文由测试内构造，不依赖真实流量，也不依赖 libpcap。
"""

from __future__ import annotations

import socket
import struct

import pytest

from nps.core.packet import Packet
from nps.decode import decode_packet

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return MAC_B + MAC_A + struct.pack("!H", ethertype) + payload


def ipv4(payload: bytes, proto: int = 17, src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
    total_len = 20 + len(payload)
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        1,
        0x4000,
        64,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return header + payload


def udp(payload: bytes, sport: int = 5000, dport: int = 5001) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo(seq: int = 1) -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, 0x1234, seq) + b"ping"
    return body[:2] + struct.pack("!H", 0) + body[4:]


def make_packet(raw: bytes, linktype: int = 1, index: int = 1) -> Packet:
    return Packet(
        index=index,
        ts=1_700_000_000.0,
        caplen=len(raw),
        wirelen=len(raw),
        linktype=linktype,
        raw=memoryview(raw),
    )


def test_udp_layers_and_summary() -> None:
    decoded = decode_packet(make_packet(ethernet(ipv4(udp(b"hello")))))
    assert decoded.protocol == "UDP"
    assert decoded.src == "10.0.0.1"
    assert decoded.dst == "10.0.0.2"
    assert decoded.summary == "5000 → 5001 Len=5"
    assert decoded.names == [
        "Ethernet II",
        "Internet Protocol Version 4",
        "User Datagram Protocol",
    ]


def test_layer_offsets_follow_frame_layout() -> None:
    decoded = decode_packet(make_packet(ethernet(ipv4(udp(b"x")))))
    by_name = {layer.name: layer for layer in decoded.layers}
    assert by_name["Ethernet II"].offset == 0
    assert by_name["Internet Protocol Version 4"].offset == 14
    assert by_name["User Datagram Protocol"].offset == 34
    # 端口字段的绝对偏移 = UDP 层偏移 + 0/2
    ports = {child.name: child.offset for child in by_name["User Datagram Protocol"].children}
    assert ports["Source Port"] == 34
    assert ports["Destination Port"] == 36


def test_tcp_syn_summary() -> None:
    tcp = struct.pack("!HHIIBBHHH", 52341, 443, 1000, 0, 0x50, 0x02, 64240, 0, 0)
    decoded = decode_packet(make_packet(ethernet(ipv4(tcp, proto=6))))
    assert decoded.protocol == "TCP"
    assert "52341 → 443" in decoded.summary
    assert "[SYN]" in decoded.summary
    assert "Len=0" in decoded.summary


def test_icmp_echo_summary() -> None:
    decoded = decode_packet(make_packet(ethernet(ipv4(icmp_echo(), proto=1))))
    assert decoded.protocol == "ICMP"
    assert "Echo (ping) request" in decoded.summary
    assert "id=0x1234" in decoded.summary


def test_arp_request() -> None:
    arp = (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1)
        + MAC_A
        + socket.inet_aton("10.0.0.1")
        + b"\x00" * 6
        + socket.inet_aton("10.0.0.2")
    )
    decoded = decode_packet(make_packet(ethernet(arp, ethertype=0x0806)))
    assert decoded.protocol == "ARP"
    assert decoded.summary == "Who has 10.0.0.2? Tell 10.0.0.1"


def test_vlan_tag_is_stripped() -> None:
    frame = MAC_B + MAC_A + struct.pack("!HHH", 0x8100, 0x0064, 0x0800) + ipv4(udp(b"x"))
    decoded = decode_packet(make_packet(frame))
    assert "802.1Q Virtual LAN" in decoded.names
    assert decoded.protocol == "UDP"


def test_dlt_null_loopback_frame() -> None:
    raw = struct.pack("<I", 2) + ipv4(udp(b"loop"))
    decoded = decode_packet(make_packet(raw, linktype=0))
    assert decoded.protocol == "UDP"
    assert decoded.names[0] == "Null/Loopback"


def test_truncated_frame_does_not_raise() -> None:
    decoded = decode_packet(make_packet(b"\x00" * 10))
    assert decoded.protocol in {"UNKNOWN", "MALFORMED"}
    assert decoded.layers


def test_empty_frame_is_safe() -> None:
    decoded = decode_packet(make_packet(b""))
    assert decoded.summary == "empty frame"


@pytest.mark.parametrize("proto,expected", [(6, "TCP"), (17, "UDP"), (1, "ICMP")])
def test_protocol_dispatch(proto: int, expected: str) -> None:
    payload = {
        6: struct.pack("!HHIIBBHHH", 1, 2, 0, 0, 0x50, 0x10, 100, 0, 0),
        17: udp(b""),
        1: icmp_echo(),
    }[proto]
    decoded = decode_packet(make_packet(ethernet(ipv4(payload, proto=proto))))
    assert decoded.protocol == expected
