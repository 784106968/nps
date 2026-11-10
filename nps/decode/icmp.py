"""ICMP / ICMPv6 解析。"""

from __future__ import annotations

from nps.decode.fields import Decoded, Field
from nps.decode.utils import u16

ICMP_TYPES = {
    0: "Echo (ping) reply",
    3: "Destination unreachable",
    5: "Redirect",
    8: "Echo (ping) request",
    11: "Time-to-live exceeded",
    12: "Parameter problem",
}

ICMPV6_TYPES = {
    1: "Destination unreachable",
    2: "Packet too big",
    3: "Time exceeded",
    128: "Echo (ping) request",
    129: "Echo (ping) reply",
    133: "Router solicitation",
    134: "Router advertisement",
    135: "Neighbor solicitation",
    136: "Neighbor advertisement",
}

_ECHO_TYPES = {0, 8, 128, 129}


def decode(
    raw: bytes,
    offset: int,
    layers: list[Field],
    decoded: Decoded,
    payload_len: int,
    version: int = 4,
) -> None:
    decoded.protocol = "ICMP" if version == 4 else "ICMPv6"
    if len(raw) < offset + 4:
        layers.append(Field(decoded.protocol, "truncated", offset, len(raw) - offset))
        decoded.summary = "truncated ICMP header"
        return

    type_code = raw[offset]
    code = raw[offset + 1]
    checksum = u16(raw, offset + 2) or 0
    names = ICMP_TYPES if version == 4 else ICMPV6_TYPES
    type_name = names.get(type_code, f"Type {type_code}")

    layer = Field(decoded.protocol, f"{type_name}, Code: {code}", offset, 8)
    layer.add("Type", f"{type_name} ({type_code})", offset, 1)
    layer.add("Code", code, offset + 1, 1)
    layer.add("Checksum", f"0x{checksum:04x}", offset + 2, 2)

    if type_code in _ECHO_TYPES and len(raw) >= offset + 8:
        identifier = u16(raw, offset + 4) or 0
        sequence = u16(raw, offset + 6) or 0
        body = max(0, payload_len - 8)
        layer.add("Identifier", f"0x{identifier:04x} ({identifier})", offset + 4, 2)
        layer.add("Sequence Number", f"{sequence} (0x{sequence:04x})", offset + 6, 2)
        if body:
            layer.add("Data", f"{body} bytes", offset + 8, body)
        layers.append(layer)
        decoded.summary = f"{type_name}  id=0x{identifier:04x}, seq={sequence}, {body} bytes"
        return

    layers.append(layer)
    decoded.summary = f"{type_name}, Code: {code}"
