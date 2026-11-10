"""IPv6 解析（固定 40 字节头，扩展头暂不展开）。"""

from __future__ import annotations

from nps.decode import icmp, tcp, udp
from nps.decode.fields import Decoded, Field
from nps.decode.utils import ipv6, u16

NEXT_HEADER_NAMES = {
    0: "Hop-by-Hop",
    6: "TCP",
    17: "UDP",
    43: "Routing",
    44: "Fragment",
    50: "ESP",
    58: "ICMPv6",
    60: "Destination Options",
}


def decode(raw: bytes, offset: int, layers: list[Field], decoded: Decoded) -> None:
    if len(raw) < offset + 40:
        layers.append(Field("Internet Protocol Version 6", "truncated", offset, len(raw) - offset))
        decoded.protocol = "IPv6"
        decoded.summary = "truncated IPv6 header"
        return

    version = raw[offset] >> 4
    traffic_class = ((raw[offset] & 0x0F) << 4) | (raw[offset + 1] >> 4)
    flow_label = ((raw[offset + 1] & 0x0F) << 16) | (u16(raw, offset + 2) or 0)
    payload_len = u16(raw, offset + 4) or 0
    next_header = raw[offset + 6]
    hop_limit = raw[offset + 7]
    src = ipv6(raw, offset + 8)
    dst = ipv6(raw, offset + 24)

    layer = Field("Internet Protocol Version 6", f"Src: {src}, Dst: {dst}", offset, 40)
    layer.add("Version", version, offset, 1)
    layer.add("Traffic Class", f"0x{traffic_class:02x}", offset, 1)
    layer.add("Flow Label", f"0x{flow_label:05x}", offset + 1, 3)
    layer.add("Payload Length", payload_len, offset + 4, 2)
    layer.add(
        "Next Header",
        f"{NEXT_HEADER_NAMES.get(next_header, 'Unknown')} ({next_header})",
        offset + 6,
        1,
    )
    layer.add("Hop Limit", hop_limit, offset + 7, 1)
    layer.add("Source Address", src, offset + 8, 16)
    layer.add("Destination Address", dst, offset + 24, 16)
    layers.append(layer)

    decoded.src = src
    decoded.dst = dst
    decoded.protocol = NEXT_HEADER_NAMES.get(next_header, f"IPv6/{next_header}")
    decoded.put(
        **{
            "ip.version": 6,
            "ip.src": src,
            "ip.dst": dst,
            "ip.proto": next_header,
            "ip.len": payload_len + 40,
            "ip.ttl": hop_limit,
        }
    )

    payload_offset = offset + 40
    payload = min(payload_len, max(0, len(raw) - payload_offset))

    if next_header == 6:
        tcp.decode(raw, payload_offset, layers, decoded, payload)
    elif next_header == 17:
        udp.decode(raw, payload_offset, layers, decoded, payload)
    elif next_header == 58:
        icmp.decode(raw, payload_offset, layers, decoded, payload, version=6)
    elif next_header in (0, 43, 44, 60):
        decoded.summary = f"{src} → {dst} {NEXT_HEADER_NAMES[next_header]} header"
        layers.append(
            Field(NEXT_HEADER_NAMES[next_header], f"{payload} bytes", payload_offset, payload)
        )
    else:
        decoded.summary = f"{src} → {dst} next header {next_header}, {payload} bytes"
