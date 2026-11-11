"""会话表：规范化、上下行统计、老化、容量与内存。"""

from __future__ import annotations

import socket
import struct
import tracemalloc

from nps.core.packet import Packet
from nps.core.session import SessionTable

CLIENT = ("10.0.0.1", 51234)
SERVER = ("93.184.216.34", 80)

_seq = 0


def _packet(frame: bytes, ts: float) -> Packet:
    global _seq
    _seq += 1
    return Packet(
        index=_seq,
        ts=ts,
        caplen=len(frame),
        wirelen=len(frame),
        linktype=1,
        raw=memoryview(frame),
    )


def _eth(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return b"\x02" * 6 + b"\x04" * 6 + struct.pack("!H", ethertype) + payload


def _ipv4(payload: bytes, proto: int, src: str, dst: str) -> bytes:
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(payload),
            1,
            0x4000,
            64,
            proto,
            0,
            socket.inet_aton(src),
            socket.inet_aton(dst),
        )
        + payload
    )


def tcp_packet(
    src: tuple[str, int],
    dst: tuple[str, int],
    flags: int,
    payload: bytes = b"",
    ts: float = 1_000.0,
) -> Packet:
    tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], 1, 0, 0x50, flags, 64240, 0, 0) + payload
    return _packet(_eth(_ipv4(tcp, 6, src[0], dst[0])), ts)


def udp_packet(
    src: tuple[str, int], dst: tuple[str, int], payload: bytes = b"x", ts: float = 1_000.0
) -> Packet:
    udp = struct.pack("!HHHH", src[1], dst[1], 8 + len(payload), 0) + payload
    return _packet(_eth(_ipv4(udp, 17, src[0], dst[0])), ts)


def icmp_packet(src: str = "10.0.0.1", dst: str = "10.0.0.2", ts: float = 1_000.0) -> Packet:
    body = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping"
    return _packet(_eth(_ipv4(body, 1, src, dst)), ts)


# ---- 规范化与方向 ----
def test_bidirectional_merge() -> None:
    table = SessionTable()
    up = tcp_packet(CLIENT, SERVER, 0x02)
    down = tcp_packet(SERVER, CLIENT, 0x12)
    session_up = table.add(up)
    session_down = table.add(down)

    assert session_up is not None and session_down is not None
    assert len(table) == 1
    assert up.stream_id == down.stream_id == 1
    assert session_up.initiator == CLIENT


def test_up_down_counters_and_bytes() -> None:
    table = SessionTable()
    packets = [
        tcp_packet(CLIENT, SERVER, 0x02),
        tcp_packet(SERVER, CLIENT, 0x12),
        tcp_packet(CLIENT, SERVER, 0x10),
    ]
    for packet in packets:
        table.add(packet)

    session = table.get(1)
    assert session is not None
    assert session.packets_up == 2
    assert session.packets_down == 1
    assert session.bytes_up == packets[0].wirelen + packets[2].wirelen
    assert session.bytes_down == packets[1].wirelen


def test_full_tcp_connection_is_one_stream() -> None:
    table = SessionTable()
    sequence = [
        tcp_packet(CLIENT, SERVER, 0x02),  # SYN
        tcp_packet(SERVER, CLIENT, 0x12),  # SYN-ACK
        tcp_packet(CLIENT, SERVER, 0x10),  # ACK
        tcp_packet(CLIENT, SERVER, 0x18, b"GET / HTTP/1.1\r\n"),  # PSH-ACK
        tcp_packet(SERVER, CLIENT, 0x18, b"HTTP/1.1 200 OK\r\n"),  # PSH-ACK
        tcp_packet(CLIENT, SERVER, 0x11),  # FIN-ACK
        tcp_packet(SERVER, CLIENT, 0x11),  # FIN-ACK
        tcp_packet(CLIENT, SERVER, 0x10),  # ACK
    ]
    for packet in sequence:
        table.add(packet)

    assert len(table) == 1
    session = table.get(1)
    assert session is not None
    assert session.packets_up + session.packets_down == len(sequence)
    assert session.packets_up == 5
    assert session.packets_down == 3
    assert {"SYN", "ACK", "PSH", "FIN"} <= session.tcp_flags


def test_stream_ids_are_sequentially_allocated() -> None:
    table = SessionTable()
    table.add(tcp_packet(CLIENT, SERVER, 0x02))
    table.add(udp_packet(("10.0.0.5", 5353), ("8.8.8.8", 53)))
    table.add(icmp_packet())

    assert len(table) == 3
    assert sorted(session.stream_id for session in table.sessions()) == [1, 2, 3]


def test_first_uplink_payload_is_captured_and_capped() -> None:
    table = SessionTable()
    table.add(tcp_packet(CLIENT, SERVER, 0x02))
    table.add(tcp_packet(SERVER, CLIENT, 0x18, b"reply-first"))
    table.add(tcp_packet(CLIENT, SERVER, 0x18, b"A" * 800))
    table.add(tcp_packet(CLIENT, SERVER, 0x18, b"second"))

    session = table.get(1)
    assert session is not None
    assert session.first_uplink_payload == b"A" * 512


def test_session_label_and_endpoints() -> None:
    table = SessionTable()
    table.add(tcp_packet(CLIENT, SERVER, 0x02))
    session = table.get(1)
    assert session is not None
    assert session.client == CLIENT
    assert session.server == SERVER
    assert session.label == "10.0.0.1:51234 ↔ 93.184.216.34:80"
    assert session.protocol == "TCP"


def test_non_ip_packet_ignored() -> None:
    table = SessionTable()
    arp = _eth(b"\x00" * 28, ethertype=0x0806)
    packet = _packet(arp, 1_000.0)
    assert table.add(packet) is None
    assert packet.stream_id is None
    assert len(table) == 0


# ---- 老化（虚拟时钟） ----
def test_udp_expires_after_60s() -> None:
    table = SessionTable()
    table.add(udp_packet(("10.0.0.5", 5353), ("8.8.8.8", 53), ts=1_000.0))

    assert table.expire(1_059.0) == 0
    assert table.expire(1_060.0) == 1
    assert len(table) == 0
    assert table.expired == 1


def test_tcp_expires_after_120s() -> None:
    table = SessionTable()
    table.add(tcp_packet(CLIENT, SERVER, 0x02, ts=1_000.0))
    assert table.expire(1_119.0) == 0
    assert table.expire(1_120.0) == 1


def test_icmp_expires_after_30s() -> None:
    table = SessionTable()
    table.add(icmp_packet(ts=1_000.0))
    assert table.expire(1_029.0) == 0
    assert table.expire(1_030.0) == 1


def test_activity_keeps_session_alive() -> None:
    table = SessionTable()
    table.add(udp_packet(("10.0.0.5", 5353), ("8.8.8.8", 53), ts=1_000.0))
    table.add(udp_packet(("10.0.0.5", 5353), ("8.8.8.8", 53), ts=1_050.0))
    assert table.expire(1_070.0) == 0
    assert table.expire(1_110.0) == 1


# ---- 容量 ----
def test_capacity_evicts_least_recently_used() -> None:
    table = SessionTable(capacity=2)
    table.add(udp_packet(("10.0.0.1", 1000), ("10.0.0.9", 53), ts=1_000.0))
    table.add(udp_packet(("10.0.0.2", 1001), ("10.0.0.9", 53), ts=1_001.0))
    # 让第一条变成最近使用
    table.add(udp_packet(("10.0.0.1", 1000), ("10.0.0.9", 53), ts=1_002.0))
    table.add(udp_packet(("10.0.0.3", 1002), ("10.0.0.9", 53), ts=1_003.0))

    assert len(table) == 2
    assert table.evicted == 1
    remaining = {session.label for session in table.sessions()}
    assert any("10.0.0.2" in label for label in remaining) is False


def test_clear_resets_everything() -> None:
    table = SessionTable(capacity=1)
    table.add(udp_packet(("10.0.0.1", 1000), ("10.0.0.9", 53)))
    table.add(udp_packet(("10.0.0.2", 1001), ("10.0.0.9", 53)))
    table.clear()

    assert len(table) == 0
    assert table.evicted == 0
    assert table.get(1) is None


def test_twenty_thousand_sessions_memory() -> None:
    table = SessionTable(capacity=20_000)
    tracemalloc.start()
    for index in range(20_000):
        source = (f"10.0.{index // 250 % 250}.{index % 250}", 1024 + index % 60000)
        table.add(udp_packet(source, ("10.9.9.9", 53), ts=float(index)))
    current, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()

    assert len(table) == 20_000
    assert peak < 200 * 1024 * 1024, f"峰值内存 {peak / 1024 / 1024:.1f} MB"
