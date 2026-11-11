"""TLS 记录层与握手解析测试。"""

from __future__ import annotations

import struct

from nps.core.packet import Packet
from nps.decode import decode_packet
from nps.decode.tls import decode as decode_tls


def client_hello(
    sni: str = "example.com",
    alpn: tuple[str, ...] = ("h2", "http/1.1"),
    versions: tuple[int, ...] = (0x0304, 0x0303),
) -> bytes:
    name = sni.encode()
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    server_name_data = len(entry).to_bytes(2, "big") + entry
    server_name_ext = b"\x00\x00" + len(server_name_data).to_bytes(2, "big") + server_name_data

    protocols = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    alpn_data = len(protocols).to_bytes(2, "big") + protocols
    alpn_ext = b"\x00\x10" + len(alpn_data).to_bytes(2, "big") + alpn_data

    version_bytes = b"".join(v.to_bytes(2, "big") for v in versions)
    sv_data = bytes([len(version_bytes)]) + version_bytes
    sv_ext = b"\x00\x2b" + len(sv_data).to_bytes(2, "big") + sv_data

    extensions = server_name_ext + alpn_ext + sv_ext
    body = (
        b"\x03\x03"
        + b"\x11" * 32
        + b"\x00"
        + (4).to_bytes(2, "big")
        + b"\x13\x01\x13\x02"
        + b"\x01\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(handshake).to_bytes(2, "big") + handshake


def server_hello(suite: int = 0x1301) -> bytes:
    extensions = b"\x00\x2b" + (3).to_bytes(2, "big") + b"\x02\x03\x04"
    body = (
        b"\x03\x03"
        + b"\x22" * 32
        + b"\x00"
        + suite.to_bytes(2, "big")
        + b"\x00"
        + len(extensions).to_bytes(2, "big")
        + extensions
    )
    handshake = b"\x02" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x03" + len(handshake).to_bytes(2, "big") + handshake


def application_data(size: int = 32) -> bytes:
    return b"\x17\x03\x03" + size.to_bytes(2, "big") + b"\x33" * size


def tcp_frame(payload: bytes, dport: int = 443) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", 50000, dport, 1, 0, 0x50, 0x18, 64240, 0, 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0x4000,
        64,
        6,
        0,
        b"\x0a\x00\x00\x01",
        b"\x5d\xb8\xd8\x22",
    )
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp


def make_packet(payload: bytes) -> Packet:
    frame = tcp_frame(payload)
    return Packet(
        index=1,
        ts=1_000.0,
        caplen=len(frame),
        wirelen=len(frame),
        linktype=1,
        raw=memoryview(frame),
    )


def flatten(field):
    yield field
    for child in field.children:
        yield from flatten(child)


def find(layers, name: str) -> list[str]:
    values = []
    for layer in layers:
        for node in flatten(layer):
            if node.name == name:
                values.append(node.value)
    return values


def test_client_hello_fields() -> None:
    decoded = decode_packet(make_packet(client_hello()))
    assert "Transport Layer Security" in decoded.names

    assert find(decoded.layers, "Host Name") == ["example.com"]
    assert find(decoded.layers, "ALPN Protocol") == ["h2", "http/1.1"]
    assert any("TLS 1.3" in value for value in find(decoded.layers, "Supported Version"))
    assert find(decoded.layers, "Content Type") == ["Handshake (22)"]
    assert find(decoded.layers, "Handshake Type") == ["Client Hello (1)"]


def test_server_hello_cipher_suite() -> None:
    decoded = decode_packet(make_packet(server_hello()))
    assert find(decoded.layers, "Handshake Type") == ["Server Hello (2)"]
    assert "TLS_AES_128_GCM_SHA256" in find(decoded.layers, "Cipher Suite")[0]


def test_application_data_is_marked_encrypted() -> None:
    decoded = decode_packet(make_packet(application_data()))
    assert "Transport Layer Security" in decoded.names
    assert find(decoded.layers, "Content Type") == ["Application Data (23)"]
    note = find(decoded.layers, "Application Data")[0]
    assert "密文" in note


def test_truncated_client_hello_does_not_raise() -> None:
    payload = client_hello()[:40]
    layers = []
    assert decode_tls(payload, 0, len(payload), layers) is not None
    assert layers[0].name == "Transport Layer Security"


def test_non_tls_payload_ignored() -> None:
    decoded = decode_packet(make_packet(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"))
    assert "Transport Layer Security" not in decoded.names


def test_tls_layer_offsets_are_absolute() -> None:
    decoded = decode_packet(make_packet(client_hello()))
    tls_layer = next(layer for layer in decoded.layers if layer.name == "Transport Layer Security")
    # 以太网 14 + IPv4 20 + TCP 20 = 54
    assert tls_layer.offset == 54
    host = next(
        node for layer in decoded.layers for node in flatten(layer) if node.name == "Host Name"
    )
    assert host.offset > tls_layer.offset
    assert host.length == len("example.com")
