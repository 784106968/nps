"""链路层解析：Ethernet II、802.1Q、DLT_NULL、DLT_LINUX_SLL、DLT_RAW。

注意：Npcap 的回环适配器上报 ``DLT_NULL``，帧首 4 字节是地址族而不是 MAC，
所以不能一律按以太网头处理（见 docs/ARCHITECTURE.md）。
"""

from __future__ import annotations

import sys

from nps.decode.fields import Field
from nps.decode.utils import mac, u16

ETHERTYPE_NAMES = {
    0x0800: "IPv4",
    0x0806: "ARP",
    0x86DD: "IPv6",
    0x8100: "802.1Q",
    0x88CC: "LLDP",
}

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_RAW_ALT = 101
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276


def _ethertype_name(value: int) -> str:
    return ETHERTYPE_NAMES.get(value, f"0x{value:04x}")


def decode_link(raw: bytes, linktype: int, layers: list[Field]) -> tuple[int | None, int]:
    """解析链路层，返回 (ethertype, 三层偏移)。"""
    if linktype == DLT_EN10MB:
        return _decode_ethernet(raw, layers)
    if linktype == DLT_NULL:
        return _decode_null(raw, layers)
    if linktype in (DLT_RAW, DLT_RAW_ALT):
        return _decode_raw(raw, layers)
    if linktype in (DLT_LINUX_SLL, DLT_LINUX_SLL2):
        return _decode_sll(raw, layers, sll2=linktype == DLT_LINUX_SLL2)
    layers.append(Field("Unknown link type", str(linktype), 0, len(raw)))
    return None, 0


def _decode_ethernet(raw: bytes, layers: list[Field]) -> tuple[int | None, int]:
    if len(raw) < 14:
        layers.append(Field("Ethernet II", "truncated", 0, len(raw)))
        return None, len(raw)

    dst = mac(raw, 0)
    src = mac(raw, 6)
    layer = Field("Ethernet II", f"Src: {src}, Dst: {dst}", 0, 14)
    layer.add("Destination", dst, 0, 6)
    layer.add("Source", src, 6, 6)
    ethertype = u16(raw, 12) or 0
    layer.add("Type", f"{_ethertype_name(ethertype)} (0x{ethertype:04x})", 12, 2)
    layers.append(layer)
    offset = 14

    while ethertype == 0x8100 and len(raw) >= offset + 4:
        tci = u16(raw, offset) or 0
        inner = u16(raw, offset + 2) or 0
        vlan = Field(
            "802.1Q Virtual LAN",
            f"PRI: {(tci >> 13) & 0x7}, DEI: {(tci >> 12) & 0x1}, ID: {tci & 0x0FFF}",
            offset,
            4,
        )
        vlan.add("Priority", (tci >> 13) & 0x7, offset, 1)
        vlan.add("DEI", (tci >> 12) & 0x1, offset, 1)
        vlan.add("VLAN ID", tci & 0x0FFF, offset, 2)
        vlan.add("Type", f"{_ethertype_name(inner)} (0x{inner:04x})", offset + 2, 2)
        layers.append(vlan)
        ethertype = inner
        offset += 4

    return ethertype, offset


def _decode_null(raw: bytes, layers: list[Field]) -> tuple[int | None, int]:
    if len(raw) < 4:
        layers.append(Field("Null/Loopback", "truncated", 0, len(raw)))
        return None, len(raw)
    family = int.from_bytes(raw[0:4], sys.byteorder)
    mapping = {2: 0x0800, 23: 0x86DD, 24: 0x86DD, 28: 0x86DD, 30: 0x86DD}
    ethertype = mapping.get(family)
    name = "IPv4" if ethertype == 0x0800 else "IPv6" if ethertype == 0x86DD else "unknown"
    layer = Field("Null/Loopback", f"Family: {family} ({name})", 0, 4)
    layer.add("Family", f"{family} ({name})", 0, 4)
    layers.append(layer)
    return ethertype, 4


def _decode_raw(raw: bytes, layers: list[Field]) -> tuple[int | None, int]:
    if not raw:
        layers.append(Field("Raw IP", "empty", 0, 0))
        return None, 0
    version = raw[0] >> 4
    if version == 4:
        layers.append(Field("Raw IPv4", "", 0, 0))
        return 0x0800, 0
    if version == 6:
        layers.append(Field("Raw IPv6", "", 0, 0))
        return 0x86DD, 0
    layers.append(Field("Raw IP", f"version {version}", 0, 0))
    return None, 0


def _decode_sll(raw: bytes, layers: list[Field], sll2: bool = False) -> tuple[int | None, int]:
    header_len = 20 if sll2 else 16
    if len(raw) < header_len:
        layers.append(Field("Linux cooked capture", "truncated", 0, len(raw)))
        return None, len(raw)
    pkttype = u16(raw, 0) or 0
    ethertype = u16(raw, 0 if sll2 else 14) or 0
    if sll2:
        ethertype = u16(raw, 0) or 0
    layer = Field("Linux cooked capture", f"Packet type: {pkttype}", 0, header_len)
    layer.add("Packet type", pkttype, 0, 2)
    layer.add("Protocol", f"{_ethertype_name(ethertype)} (0x{ethertype:04x})", header_len - 2, 2)
    layers.append(layer)
    return ethertype, header_len
