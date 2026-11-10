"""生成合成 PCAP 测试数据（不含任何真实流量）。

    python scripts/make_fixtures.py

产物：tests/fixtures/sample_traffic.pcap
包含 4 个 UDP 包与 2 个 ICMP Echo 包，用于离线回放、过滤与解析测试。
"""

from __future__ import annotations

import socket
import struct
from pathlib import Path

FIXTURE = Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "sample_traffic.pcap"

PCAP_MAGIC = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
SNAPLEN = 65535

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")

IP_A = "10.0.0.1"
IP_B = "10.0.0.2"
BASE_TS = 1_700_000_000


def checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for index in range(0, len(data), 2):
        total += (data[index] << 8) + data[index + 1]
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def ipv4_header(src: str, dst: str, proto: int, payload_len: int, ident: int) -> bytes:
    total_len = 20 + payload_len
    header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_len,
        ident,
        0x4000,  # DF
        64,
        proto,
        0,
        socket.inet_aton(src),
        socket.inet_aton(dst),
    )
    return header[:10] + struct.pack("!H", checksum(header)) + header[12:]


def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return MAC_B + MAC_A + struct.pack("!H", ethertype) + payload


def udp_packet(sport: int, dport: int, payload: bytes, ident: int) -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    return ethernet(ipv4_header(IP_A, IP_B, 17, len(udp), ident) + udp)


def icmp_echo(seq: int, payload: bytes, ident: int) -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, 0x1234, seq) + payload
    icmp = body[:2] + struct.pack("!H", checksum(body)) + body[4:]
    return ethernet(ipv4_header(IP_A, IP_B, 1, len(icmp), ident) + icmp)


def write_pcap(path: Path, frames: list[bytes]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    header = struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET)
    with path.open("wb") as handle:
        handle.write(header)
        for index, frame in enumerate(frames):
            ts_sec = BASE_TS + index
            ts_usec = index * 1000
            handle.write(struct.pack("<IIII", ts_sec, ts_usec, len(frame), len(frame)))
            handle.write(frame)


def build() -> list[bytes]:
    frames = [
        udp_packet(5000, 5001, b"NPS-fixture-0000", 1),
        udp_packet(5000, 5001, b"NPS-fixture-0001", 2),
        udp_packet(5000, 5001, b"NPS-fixture-0002", 3),
        icmp_echo(1, b"NPS-icmp-0000", 4),
        udp_packet(5000, 5001, b"NPS-fixture-0003", 5),
        icmp_echo(2, b"NPS-icmp-0001", 6),
    ]
    return frames


def main() -> int:
    frames = build()
    write_pcap(FIXTURE, frames)
    print(f"已生成 {FIXTURE}（{len(frames)} 个包，{FIXTURE.stat().st_size} 字节）")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
