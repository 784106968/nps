"""IPv4 解析。"""

from __future__ import annotations

from nps.decode import icmp, tcp, udp
from nps.decode.fields import Decoded, Field
from nps.decode.utils import ipv4, u16

PROTOCOL_NAMES = {
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    17: "UDP",
    41: "IPv6",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
}

_FLAG_BITS = ((0x8000, "Reserved"), (0x4000, "Don't fragment"), (0x2000, "More fragments"))


def decode(raw: bytes, offset: int, layers: list[Field], decoded: Decoded) -> None:
    if len(raw) < offset + 20:
        layers.append(Field("Internet Protocol Version 4", "truncated", offset, len(raw) - offset))
        decoded.protocol = "IPv4"
        decoded.summary = "truncated IPv4 header"
        return

    version = raw[offset] >> 4
    ihl = (raw[offset] & 0x0F) * 4
    if ihl < 20:
        ihl = 20
    total_len = u16(raw, offset + 2) or 0
    identification = u16(raw, offset + 4) or 0
    flags_frag = u16(raw, offset + 6) or 0
    ttl = raw[offset + 8]
    proto = raw[offset + 9]
    checksum = u16(raw, offset + 10) or 0
    src = ipv4(raw, offset + 12)
    dst = ipv4(raw, offset + 16)

    layer = Field("Internet Protocol Version 4", f"Src: {src}, Dst: {dst}", offset, ihl)
    layer.add("Version", version, offset, 1)
    layer.add("Header Length", f"{ihl} bytes ({ihl // 4})", offset, 1)
    layer.add("Differentiated Services", f"0x{raw[offset + 1]:02x}", offset + 1, 1)
    layer.add("Total Length", total_len, offset + 2, 2)
    layer.add("Identification", f"0x{identification:04x} ({identification})", offset + 4, 2)

    flag_names = [name for bit, name in _FLAG_BITS if flags_frag & bit]
    flags_node = layer.add(
        "Flags",
        f"0x{flags_frag >> 13:03b}" + (f" ({', '.join(flag_names)})" if flag_names else ""),
        offset + 6,
        1,
    )
    for bit, name in _FLAG_BITS:
        flags_node.add(name, 1 if flags_frag & bit else 0, offset + 6, 1)
    layer.add("Fragment Offset", flags_frag & 0x1FFF, offset + 6, 2)

    layer.add("Time to Live", ttl, offset + 8, 1)
    layer.add("Protocol", f"{PROTOCOL_NAMES.get(proto, 'Unknown')} ({proto})", offset + 9, 1)
    layer.add("Header Checksum", f"0x{checksum:04x}", offset + 10, 2)
    layer.add("Source Address", src, offset + 12, 4)
    layer.add("Destination Address", dst, offset + 16, 4)
    layers.append(layer)

    decoded.src = src
    decoded.dst = dst
    decoded.protocol = PROTOCOL_NAMES.get(proto, f"IPv4/{proto}")

    payload_offset = offset + ihl
    payload_len = max(0, (total_len or len(raw) - offset) - ihl)
    payload_len = min(payload_len, max(0, len(raw) - payload_offset))

    if proto == 6:
        tcp.decode(raw, payload_offset, layers, decoded, payload_len)
    elif proto == 17:
        udp.decode(raw, payload_offset, layers, decoded, payload_len)
    elif proto == 1:
        icmp.decode(raw, payload_offset, layers, decoded, payload_len)
    else:
        decoded.summary = f"{src} → {dst} protocol {proto}, {payload_len} bytes"
        if payload_len:
            layers.append(Field("Payload", f"{payload_len} bytes", payload_offset, payload_len))
