"""TLS 记录层与握手解析（只读，不解密）。

只解析握手阶段的明文字段：

- 记录头：ContentType / Version / Length；
- ClientHello / ServerHello：版本、Random、Session ID、Cipher Suites、Extensions；
- 常用扩展：server_name（SNI）、application_layer_protocol_negotiation（ALPN）、
  supported_versions、supported_groups。

应用数据（ContentType=23）只标注长度，载荷本身仍是密文——
「能抓到、能读出握手元数据、读不到内容」正是加密边界的体现。
"""

from __future__ import annotations

from nps.decode.fields import Field

CONTENT_TYPES = {
    20: "Change Cipher Spec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
}

HANDSHAKE_TYPES = {
    1: "Client Hello",
    2: "Server Hello",
    4: "New Session Ticket",
    8: "Encrypted Extensions",
    11: "Certificate",
    20: "Finished",
}

VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0xC02B: "ECDHE-ECDSA-AES128-GCM-SHA256",
    0xC02F: "ECDHE-RSA-AES128-GCM-SHA256",
    0xC030: "ECDHE-RSA-AES256-GCM-SHA384",
    0xCCA8: "ECDHE-RSA-CHACHA20-POLY1305",
}

EXTENSION_NAMES = {
    0: "server_name",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "application_layer_protocol_negotiation",
    23: "extended_master_secret",
    43: "supported_versions",
    45: "psk_key_exchange_modes",
    51: "key_share",
}

MAX_CIPHERS_SHOWN = 8


def _version_text(value: int) -> str:
    name = VERSIONS.get(value, "Unknown")
    return f"{name} (0x{value:04x})"


def _u16(raw: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(raw):
        return None
    return int.from_bytes(raw[offset : offset + 2], "big")


def _u24(raw: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 3 > len(raw):
        return None
    return int.from_bytes(raw[offset : offset + 3], "big")


def decode(raw: bytes, offset: int, length: int, layers: list[Field]) -> Field | None:
    """解析一段 TLS 记录并追加到 layers；不是 TLS 返回 None。"""
    if length < 5 or offset + 5 > len(raw):
        return None
    content_type = raw[offset]
    version = _u16(raw, offset + 1)
    record_length = _u16(raw, offset + 3)
    if content_type not in CONTENT_TYPES or version is None or record_length is None:
        return None
    if version < 0x0300 or version > 0x0304:
        return None

    record_end = min(offset + 5 + record_length, len(raw), offset + length)
    layer = Field(
        "Transport Layer Security",
        f"{CONTENT_TYPES[content_type]}, Version: {_version_text(version)}",
        offset,
        record_end - offset,
    )
    layer.add("Content Type", f"{CONTENT_TYPES[content_type]} ({content_type})", offset, 1)
    layer.add("Version", _version_text(version), offset + 1, 2)
    layer.add("Length", record_length, offset + 3, 2)

    if content_type == 23:
        layer.add("Application Data", f"{record_end - offset - 5} bytes（密文）", offset + 5, 0)
    elif content_type == 21 and record_end > offset + 5:
        layer.add("Alert Level", raw[offset + 5], offset + 5, 1)
        if offset + 6 < record_end:
            layer.add("Alert Description", raw[offset + 6], offset + 6, 1)
    elif content_type == 22:
        _decode_handshake(raw, offset + 5, record_end, layer)

    layers.append(layer)
    return layer


def _decode_handshake(raw: bytes, offset: int, end: int, layer: Field) -> None:
    if offset + 4 > end:
        layer.add("Handshake", "truncated", offset, 0)
        return
    handshake_type = raw[offset]
    body_length = _u24(raw, offset + 1) or 0
    name = HANDSHAKE_TYPES.get(handshake_type, f"Type {handshake_type}")
    node = layer.add("Handshake Protocol", name, offset, min(4 + body_length, end - offset))
    node.add("Handshake Type", f"{name} ({handshake_type})", offset, 1)
    node.add("Length", body_length, offset + 1, 3)

    body = offset + 4
    body_end = min(body + body_length, end)
    if handshake_type == 1:
        _decode_hello(raw, body, body_end, node, client=True)
    elif handshake_type == 2:
        _decode_hello(raw, body, body_end, node, client=False)


def _decode_hello(raw: bytes, offset: int, end: int, parent: Field, client: bool) -> None:
    if offset + 34 > end:
        parent.add("Hello", "truncated", offset, max(0, end - offset))
        return

    version = _u16(raw, offset) or 0
    parent.add("Version", _version_text(version), offset, 2)
    random = raw[offset + 2 : offset + 34]
    parent.add("Random", random[:16].hex(" ") + " …", offset + 2, 32)
    cursor = offset + 34

    if cursor + 1 > end:
        return
    session_id_length = raw[cursor]
    parent.add("Session ID Length", session_id_length, cursor, 1)
    cursor += 1 + session_id_length
    if cursor > end:
        return

    if client:
        suites_length = _u16(raw, cursor) or 0
        parent.add("Cipher Suites Length", suites_length, cursor, 2)
        cursor += 2
        suites_end = min(cursor + suites_length, end)
        suites_node = parent.add("Cipher Suites", f"{suites_length // 2} 个", cursor, suites_length)
        shown = 0
        while cursor + 2 <= suites_end and shown < MAX_CIPHERS_SHOWN:
            suite = _u16(raw, cursor) or 0
            suites_node.add(
                CIPHER_SUITES.get(suite, f"Cipher 0x{suite:04x}"),
                f"0x{suite:04x}",
                cursor,
                2,
            )
            cursor += 2
            shown += 1
        cursor = suites_end

        if cursor + 1 > end:
            return
        compression_length = raw[cursor]
        parent.add("Compression Methods Length", compression_length, cursor, 1)
        cursor += 1 + compression_length
    else:
        if cursor + 3 > end:
            return
        suite = _u16(raw, cursor) or 0
        parent.add("Cipher Suite", CIPHER_SUITES.get(suite, f"0x{suite:04x}"), cursor, 2)
        cursor += 2
        parent.add("Compression Method", raw[cursor], cursor, 1)
        cursor += 1

    if cursor + 2 > end:
        return
    extensions_length = _u16(raw, cursor) or 0
    extensions_node = parent.add("Extensions", f"{extensions_length} bytes", cursor, 2)
    cursor += 2
    extensions_end = min(cursor + extensions_length, end)
    while cursor + 4 <= extensions_end:
        extension_type = _u16(raw, cursor) or 0
        extension_length = _u16(raw, cursor + 2) or 0
        data_offset = cursor + 4
        data_end = min(data_offset + extension_length, extensions_end)
        name = EXTENSION_NAMES.get(extension_type, f"Extension {extension_type}")
        node = extensions_node.add(
            f"{name} (len={extension_length})",
            "",
            cursor,
            data_end - cursor,
        )
        _decode_extension(raw, extension_type, data_offset, data_end, node)
        cursor = data_offset + extension_length
        if cursor > extensions_end:
            break


def _decode_extension(raw: bytes, extension_type: int, offset: int, end: int, node: Field) -> None:
    if extension_type == 0:  # server_name
        list_length = _u16(raw, offset)
        if list_length is None:
            return
        cursor = offset + 2
        while cursor + 3 <= end:
            name_type = raw[cursor]
            name_length = _u16(raw, cursor + 1) or 0
            name_offset = cursor + 3
            if name_offset + name_length > end:
                break
            try:
                text = raw[name_offset : name_offset + name_length].decode("idna")
            except (UnicodeDecodeError, ValueError):
                text = raw[name_offset : name_offset + name_length].decode("latin-1")
            label = "Host Name" if name_type == 0 else f"Name Type {name_type}"
            node.add(label, text, name_offset, name_length)
            cursor = name_offset + name_length

    elif extension_type == 16:  # ALPN
        list_length = _u16(raw, offset)
        if list_length is None:
            return
        cursor = offset + 2
        while cursor + 1 <= end:
            name_length = raw[cursor]
            name_offset = cursor + 1
            if name_offset + name_length > end:
                break
            text = raw[name_offset : name_offset + name_length].decode("latin-1")
            node.add("ALPN Protocol", text, name_offset, name_length)
            cursor = name_offset + name_length

    elif extension_type == 43:  # supported_versions
        list_length = raw[offset] if offset < end else 0
        cursor = offset + 1
        while cursor + 2 <= end and cursor + 2 <= offset + 1 + list_length:
            version = _u16(raw, cursor) or 0
            node.add("Supported Version", _version_text(version), cursor, 2)
            cursor += 2

    elif extension_type == 10:  # supported_groups
        list_length = _u16(raw, offset)
        if list_length is None:
            return
        node.add("Groups Length", list_length, offset, 2)
