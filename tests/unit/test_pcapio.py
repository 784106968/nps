"""PCAP 写出测试（不依赖 libpcap）。"""

from __future__ import annotations

import struct

import pytest

from nps.core.packet import Packet
from nps.pcapio import read_pcap_header, write_pcap


def make_packet(index: int, payload: bytes, ts: float = 1_700_000_000.25) -> Packet:
    return Packet(
        index=index,
        ts=ts,
        caplen=len(payload),
        wirelen=len(payload) + 4,
        linktype=1,
        raw=memoryview(payload),
    )


def test_write_and_read_header(tmp_path) -> None:
    path = tmp_path / "out.pcap"
    packets = [make_packet(1, b"\x00" * 20), make_packet(2, b"\xff" * 30)]
    assert write_pcap(path, packets) == 2

    linktype, magic = read_pcap_header(path)
    assert linktype == 1
    assert magic == 0xA1B2C3D4


def test_record_layout(tmp_path) -> None:
    path = tmp_path / "layout.pcap"
    write_pcap(path, [make_packet(1, b"\x01\x02\x03", ts=1_700_000_000.5)])

    raw = path.read_bytes()
    assert len(raw) == 24 + 16 + 3
    ts_sec, ts_usec, caplen, wirelen = struct.unpack("<IIII", raw[24:40])
    assert ts_sec == 1_700_000_000
    assert ts_usec == 500_000
    assert caplen == 3
    assert wirelen == 7
    assert raw[40:] == b"\x01\x02\x03"


def test_empty_input_requires_linktype(tmp_path) -> None:
    with pytest.raises(ValueError):
        write_pcap(tmp_path / "empty.pcap", [])


def test_empty_input_with_linktype(tmp_path) -> None:
    path = tmp_path / "empty.pcap"
    assert write_pcap(path, [], linktype=1) == 0
    assert read_pcap_header(path) == (1, 0xA1B2C3D4)


def test_short_file_rejected(tmp_path) -> None:
    path = tmp_path / "short.pcap"
    path.write_bytes(b"\x00" * 10)
    with pytest.raises(ValueError):
        read_pcap_header(path)
