"""解析调度入口。

不可信 PCAP 可能任意畸形，这里兜住所有异常，确保解析失败只影响单个包，
不会把整个界面带崩（见 NPS-Readme.md §12）。
"""

from __future__ import annotations

from nps.core.packet import Packet
from nps.decode import arp, ipv4, ipv6, link
from nps.decode.fields import Decoded, Field

ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_ARP = 0x0806
ETHERTYPE_IPV6 = 0x86DD


def decode_packet(packet: Packet) -> Decoded:
    raw = bytes(packet.raw)
    decoded = Decoded()
    if not raw:
        decoded.layers.append(Field("Empty frame", "", 0, 0))
        decoded.summary = "empty frame"
        return decoded

    try:
        ethertype, offset = link.decode_link(raw, packet.linktype, decoded.layers)
        if ethertype == ETHERTYPE_ARP:
            arp.decode(raw, offset, decoded.layers, decoded)
        elif ethertype == ETHERTYPE_IPV4:
            ipv4.decode(raw, offset, decoded.layers, decoded)
        elif ethertype == ETHERTYPE_IPV6:
            ipv6.decode(raw, offset, decoded.layers, decoded)
        else:
            name = link.ETHERTYPE_NAMES.get(ethertype or -1, "UNKNOWN")
            decoded.protocol = name
            decoded.summary = f"{name}, {len(raw)} bytes"
    except Exception as exc:  # 解析器绝不把异常抛给界面
        decoded.layers.append(Field("Malformed packet", f"解析异常：{exc}", 0, len(raw)))
        decoded.protocol = "MALFORMED"
        decoded.summary = f"malformed: {exc.__class__.__name__}"

    return decoded
