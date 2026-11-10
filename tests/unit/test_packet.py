"""包模型测试。"""

from __future__ import annotations

from nps.core.packet import Packet


def make_packet(
    raw: bytes = b"\x00" * 20,
    caplen: int | None = None,
    wirelen: int | None = None,
) -> Packet:
    caplen = len(raw) if caplen is None else caplen
    wirelen = len(raw) if wirelen is None else wirelen
    return Packet(
        index=1,
        ts=1_700_000_000.0,
        caplen=caplen,
        wirelen=wirelen,
        linktype=1,
        raw=memoryview(raw),
    )


def test_truncated_flag() -> None:
    assert make_packet(raw=b"\x00" * 10, caplen=10, wirelen=1500).truncated is True
    assert make_packet(raw=b"\x00" * 10, caplen=10, wirelen=10).truncated is False


def test_raw_view_is_readonly() -> None:
    packet = make_packet()
    assert packet.raw.readonly is True


def test_head_hex_limits_length() -> None:
    packet = make_packet(raw=bytes(range(16)))
    assert packet.head_hex(4) == "00 01 02 03"


def test_timestamp_text_has_milliseconds() -> None:
    text = make_packet().ts_text
    assert len(text) == 12 and text.count(":") == 2


def test_optional_fields_default_to_none() -> None:
    packet = make_packet()
    assert packet.layers is None
    assert packet.stream_id is None
    assert packet.protocol is None
