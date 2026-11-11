"""DPI 签名匹配与会话层集成。"""

from __future__ import annotations

import os
import struct

import pytest

from nps.core.packet import Packet
from nps.core.session import SessionTable
from nps.decode.dpi import classify, load_signatures, match_payload

HTTP_GET = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"
HTTP_POST = b"POST /login HTTP/1.1\r\nContent-Length: 0\r\n\r\n"
HTTP_RESPONSE = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
TLS_HELLO = b"\x16\x03\x01\x00\x2f\x01\x00\x00\x2b\x03\x03" + b"\x00" * 40
SSH_BANNER = b"SSH-2.0-OpenSSH_9.6\r\n"
BITTORRENT = b"\x13BitTorrent protocol" + b"\x00" * 8 + b"\x11" * 40


def dns_query(qname: str = "example.com") -> bytes:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    encoded = b""
    for label in qname.split("."):
        encoded += bytes([len(label)]) + label.encode()
    encoded += b"\x00"
    return header + encoded + struct.pack("!HH", 1, 1)


def dns_response() -> bytes:
    return struct.pack("!HHHHHH", 0x1234, 0x8180, 1, 1, 0, 0) + b"\x00" * 20


# ---- 签名 ----
def test_signatures_load() -> None:
    signatures = load_signatures()
    protocols = {signature.protocol for signature in signatures}
    assert {"HTTP", "TLS", "SSH", "BitTorrent", "DNS"} <= protocols


@pytest.mark.parametrize(
    "payload,expected",
    [
        (HTTP_GET, "HTTP"),
        (HTTP_POST, "HTTP"),
        (TLS_HELLO, "TLS"),
        (SSH_BANNER, "SSH"),
        (BITTORRENT, "BitTorrent"),
        (dns_query(), "DNS"),
    ],
)
def test_positive_samples(payload: bytes, expected: str) -> None:
    matched = match_payload(payload, "uplink")
    assert matched is not None, f"{expected} 未被识别"
    assert matched.protocol == expected


def test_http_host_header_alone_matches() -> None:
    matched = match_payload(b"Host: example.com\r\nUser-Agent: curl\r\n\r\n", "uplink")
    assert matched is not None
    assert matched.protocol == "HTTP"


def test_http_response_matches_downlink() -> None:
    matched = match_payload(HTTP_RESPONSE, "downlink")
    assert matched is not None and matched.protocol == "HTTP"
    assert match_payload(HTTP_RESPONSE, "uplink") is None


@pytest.mark.parametrize(
    "payload",
    [
        b"",
        b"\x00" * 64,
        b"SSH-3.0-fake",  # 版本号不匹配
        b"GET",  # 太短
        dns_response(),  # QR=1 是响应，不是查询
        b"\x13NotBitTorrent protocol",
        os.urandom(48),
    ],
)
def test_negative_samples(payload: bytes) -> None:
    assert match_payload(payload, "uplink") is None


def test_dns_requires_single_question() -> None:
    header = struct.pack("!HHHHHH", 0x1234, 0x0100, 2, 0, 0, 0)
    assert match_payload(header + b"\x00" * 20, "uplink") is None


# ---- 端口启发式 ----
def test_port_hint_is_marked_as_port() -> None:
    protocol, confidence, note = classify(None, None, 50000, 443, 6)
    assert (protocol, confidence) == ("TLS", "port")
    assert "443" in note


def test_dpi_overrides_port_hint() -> None:
    protocol, confidence, note = classify(HTTP_GET, None, 50000, 443, 6)
    assert (protocol, confidence) == ("HTTP", "dpi")
    assert "HTTP" in note or "请求行" in note


def test_unknown_port_without_payload() -> None:
    assert classify(None, None, 50000, 12345, 6) == (None, None, "")


# ---- 会话集成 ----
def _eth(payload: bytes, proto: int = 6) -> bytes:
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        1,
        0x4000,
        64,
        proto,
        0,
        b"\x0a\x00\x00\x01",
        b"\x0a\x00\x00\x02",
    )
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + payload


def tcp_payload(sport: int, dport: int, payload: bytes, flags: int = 0x18) -> Packet:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 64240, 0, 0) + payload
    frame = _eth(tcp)
    return Packet(
        index=1,
        ts=1_000.0,
        caplen=len(frame),
        wirelen=len(frame),
        linktype=1,
        raw=memoryview(frame),
    )


def test_session_classifies_by_dpi() -> None:
    table = SessionTable()
    table.add(tcp_payload(50000, 12345, HTTP_GET))
    session = table.get(1)
    assert session is not None
    assert session.app_protocol == "HTTP"
    assert session.confidence == "dpi"


def test_session_starts_with_port_hint_then_upgrades() -> None:
    table = SessionTable()
    table.add(tcp_payload(50000, 443, b"", flags=0x02))
    session = table.get(1)
    assert session is not None
    assert (session.app_protocol, session.confidence) == ("TLS", "port")

    table.add(tcp_payload(50000, 443, TLS_HELLO))
    assert (session.app_protocol, session.confidence) == ("TLS", "dpi")


def test_session_without_payload_keeps_transport_protocol() -> None:
    table = SessionTable()
    table.add(tcp_payload(50000, 12345, b"", flags=0x02))
    session = table.get(1)
    assert session is not None
    assert session.app_protocol is None
    assert session.protocol == "TCP"
