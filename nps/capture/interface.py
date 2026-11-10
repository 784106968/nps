"""设备枚举。

Windows 下回环设备名形如 ``\\Device\\NPF_Loopback``，需要单独标注，
因为它既不出现在普通网卡列表中，也不支持混杂模式。
"""

from __future__ import annotations

import ctypes
from ctypes import POINTER, byref, create_string_buffer
from dataclasses import dataclass

from nps.capture.libpcap import (
    PCAP_ERRBUF_SIZE,
    PCAP_IF_LOOPBACK,
    PcapError,
    PcapIf,
    errbuf_text,
    load_library,
)

_LOOPBACK_EXACT = {"lo", "lo0", "loopback"}
_PSEUDO_ANY = "any"


def is_loopback_name(name: str) -> bool:
    lowered = name.strip().lower()
    if lowered in _LOOPBACK_EXACT:
        return True
    return "loopback" in lowered or "npf_loopback" in lowered


@dataclass(frozen=True, slots=True)
class Interface:
    name: str
    description: str = ""
    is_loopback: bool = False
    flags: int = 0

    @property
    def is_pseudo(self) -> bool:
        """Linux 的 ``any`` 是伪设备，部分设置项语义不同。"""
        return self.name.strip().lower() == _PSEUDO_ANY

    @property
    def promisc_supported(self) -> bool:
        return not self.is_loopback and not self.is_pseudo

    @property
    def label(self) -> str:
        tags = []
        if self.is_loopback:
            tags.append("回环")
        if self.is_pseudo:
            tags.append("伪设备")
        suffix = f"  [{'/'.join(tags)}]" if tags else ""
        desc = f"  {self.description.strip()}" if self.description.strip() else ""
        return f"{self.name}{suffix}{desc}"


def list_interfaces(lib: ctypes.CDLL | None = None) -> list[Interface]:
    """枚举可用设备；失败时抛 PcapError。"""
    lib = load_library() if lib is None else lib
    alldevs = POINTER(PcapIf)()
    errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
    if lib.pcap_findalldevs(byref(alldevs), errbuf) != 0:
        raise PcapError(f"枚举网卡失败：{errbuf_text(errbuf) or '未知原因'}")

    devices: list[Interface] = []
    try:
        node = alldevs
        while node:
            entry = node.contents
            name = (entry.name or b"").decode("utf-8", errors="replace")
            description = (entry.description or b"").decode("utf-8", errors="replace")
            if name:
                loopback = bool(entry.flags & PCAP_IF_LOOPBACK) or is_loopback_name(name)
                devices.append(
                    Interface(
                        name=name,
                        description=description,
                        is_loopback=loopback,
                        flags=int(entry.flags),
                    )
                )
            node = entry.next
    finally:
        lib.pcap_freealldevs(alldevs)
    return devices


def choose_default(devices: list[Interface]) -> Interface:
    """优先选带描述的非回环网卡。"""
    if not devices:
        raise PcapError("没有可用网卡，请确认 Npcap/libpcap 已安装且有权限")
    for device in devices:
        if not device.is_loopback and not device.is_pseudo and device.description:
            return device
    for device in devices:
        if not device.is_loopback and not device.is_pseudo:
            return device
    return devices[0]
