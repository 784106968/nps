"""解析器共用的字节读取与格式化工具。

所有读取都做边界判断：抓到的包可能被 snaplen 截断，也可能本身畸形，
解析器不允许因此抛异常。
"""

from __future__ import annotations

import ipaddress
import socket


def u8(raw: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 1 > len(raw):
        return None
    return raw[offset]


def u16(raw: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(raw):
        return None
    return int.from_bytes(raw[offset : offset + 2], "big")


def u32(raw: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(raw):
        return None
    return int.from_bytes(raw[offset : offset + 4], "big")


def mac(raw: bytes, offset: int) -> str:
    if offset + 6 > len(raw):
        return "-"
    return ":".join(f"{byte:02x}" for byte in raw[offset : offset + 6])


def ipv4(raw: bytes, offset: int) -> str:
    if offset + 4 > len(raw):
        return "-"
    return socket.inet_ntoa(raw[offset : offset + 4])


def ipv6(raw: bytes, offset: int) -> str:
    if offset + 16 > len(raw):
        return "-"
    try:
        return str(ipaddress.IPv6Address(raw[offset : offset + 16]))
    except ValueError:  # pragma: no cover - 长度已校验，理论上不会走到
        return raw[offset : offset + 16].hex()


def mac_to_bytes(text: str) -> bytes:  # pragma: no cover - 仅测试/工具使用
    return bytes(int(part, 16) for part in text.split(":"))


TCP_FLAGS = (
    (0x100, "NS"),
    (0x080, "CWR"),
    (0x040, "ECE"),
    (0x020, "URG"),
    (0x010, "ACK"),
    (0x008, "PSH"),
    (0x004, "RST"),
    (0x002, "SYN"),
    (0x001, "FIN"),
)


def tcp_flag_names(flag_byte: int) -> list[str]:
    return [name for bit, name in TCP_FLAGS if flag_byte & bit]


def format_tcp_flags(flag_byte: int) -> str:
    names = tcp_flag_names(flag_byte)
    return ", ".join(names) if names else "None"
