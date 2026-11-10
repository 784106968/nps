"""ARP 解析（仅以太网/IPv4 组合，其他链路类型按原始字段展示）。"""

from __future__ import annotations

from nps.decode.fields import Decoded, Field
from nps.decode.utils import ipv4, mac, u16

OPER_NAMES = {1: "request", 2: "reply", 3: "request reverse", 4: "reply reverse"}


def decode(raw: bytes, offset: int, layers: list[Field], decoded: Decoded) -> None:
    if len(raw) < offset + 8:
        layers.append(Field("Address Resolution Protocol", "truncated", offset, len(raw) - offset))
        decoded.protocol = "ARP"
        decoded.summary = "truncated ARP header"
        return

    hardware_type = u16(raw, offset) or 0
    protocol_type = u16(raw, offset + 2) or 0
    hardware_len = raw[offset + 4]
    protocol_len = raw[offset + 5]
    operation = u16(raw, offset + 6) or 0

    needed = 8 + 2 * hardware_len + 2 * protocol_len
    layer = Field(
        "Address Resolution Protocol", OPER_NAMES.get(operation, f"op {operation}"), offset, needed
    )
    layer.add("Hardware type", f"Ethernet ({hardware_type})", offset, 2)
    layer.add("Protocol type", f"IPv4 (0x{protocol_type:04x})", offset + 2, 2)
    layer.add("Hardware size", hardware_len, offset + 4, 1)
    layer.add("Protocol size", protocol_len, offset + 5, 1)
    layer.add("Opcode", f"{OPER_NAMES.get(operation, 'unknown')} ({operation})", offset + 6, 2)

    cursor = offset + 8
    sender_mac = sender_ip = target_mac = target_ip = "-"
    if len(raw) >= cursor + 2 * hardware_len + 2 * protocol_len:
        sender_mac = mac(raw, cursor)
        cursor += hardware_len
        sender_ip = (
            ipv4(raw, cursor) if protocol_len == 4 else raw[cursor : cursor + protocol_len].hex()
        )
        cursor += protocol_len
        target_mac = mac(raw, cursor)
        cursor += hardware_len
        target_ip = (
            ipv4(raw, cursor) if protocol_len == 4 else raw[cursor : cursor + protocol_len].hex()
        )

        layer.add("Sender MAC address", sender_mac, offset + 8, hardware_len)
        layer.add("Sender IP address", sender_ip, offset + 8 + hardware_len, protocol_len)
        layer.add(
            "Target MAC address",
            target_mac,
            offset + 8 + hardware_len + protocol_len,
            hardware_len,
        )
        layer.add(
            "Target IP address",
            target_ip,
            offset + 8 + 2 * hardware_len + protocol_len,
            protocol_len,
        )

    layers.append(layer)
    decoded.protocol = "ARP"
    decoded.src = sender_ip
    decoded.dst = target_ip
    decoded.put(**{"arp.op": operation, "arp.sender": sender_ip, "arp.target": target_ip})
    if operation == 1:
        decoded.summary = f"Who has {target_ip}? Tell {sender_ip}"
    elif operation == 2:
        decoded.summary = f"{sender_ip} is at {sender_mac}"
    else:
        decoded.summary = f"ARP {OPER_NAMES.get(operation, operation)} {sender_ip} → {target_ip}"
