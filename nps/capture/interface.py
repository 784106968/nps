"""设备枚举。

Windows 下回环设备名形如 ``\\Device\\NPF_Loopback``，需要单独标注，
因为它既不出现在普通网卡列表中，也不支持混杂模式。
"""

from __future__ import annotations

import ctypes
import locale
import sys
import unicodedata
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

_REPLACEMENT_CHAR = "\ufffd"
# 控制/格式/代理/私用/未分配字符不参与展示
_HIDDEN_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn"}


def _clean_text(text: str) -> str:
    """移除替换字符、控制字符与零宽字符，并压缩空白。"""
    kept = []
    for char in text:
        if char == _REPLACEMENT_CHAR:
            continue
        if unicodedata.category(char) in _HIDDEN_CATEGORIES:
            if char in "\t\r\n":
                kept.append(" ")
            continue
        kept.append(char)
    return " ".join("".join(kept).split())


def _is_meaningful(text: str) -> bool:
    """至少 30% 的可见字符是字母/数字/汉字，避免把纯符号乱码当成名称。"""
    visible = [char for char in text if not char.isspace()]
    if not visible:
        return False
    alnum = sum(1 for char in visible if char.isalnum())
    return alnum / len(visible) >= 0.3


def decode_device_text(raw: bytes | None) -> str:
    """按平台回退解码设备描述，无法得到可信文本时返回空串。

    Windows 上 ``pcap_findalldevs`` 的描述可能是 ANSI（中文系统为 GBK），
    也可能是 UTF-8；直接 ``errors="replace"`` 会产生 U+FFFD 乱码。
    这里依次尝试 UTF-8、UTF-16（带 BOM）、系统首选编码、mbcs、GB18030，
    全部失败或结果不可信时交给调用方使用默认名称。
    """
    if not raw:
        return ""

    # 带 BOM 的 UTF-16 优先；否则 UTF-8 成功即视为最终结果。
    # 不继续用 GBK 兜底，避免把 U+FFFD/控制字节解码成"锟斤拷"式乱码。
    if raw[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            text = raw.decode("utf-16")
        except UnicodeDecodeError:
            text = ""
        cleaned = _clean_text(text)
        return cleaned if _is_meaningful(cleaned) else ""

    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = None
    if text is not None:
        cleaned = _clean_text(text)
        return cleaned if _is_meaningful(cleaned) else ""

    # 中文 Windows 的 Npcap 描述通常是 GBK；英文 Windows 的 cp1252 几乎能解码任意字节，
    # 若先尝试 locale 会把 GBK 解成拉丁乱码，因此 GB18030/GBK 优先，locale/mbcs 兜底西文。
    candidates = ["gb18030", "gbk"]
    if sys.platform == "win32":
        candidates.append("mbcs")
    candidates.append(locale.getpreferredencoding(False))

    seen: set[str] = set()
    for encoding in candidates:
        if not encoding:
            continue
        normalized = encoding.lower()
        if normalized in seen:
            continue
        seen.add(normalized)
        try:
            text = raw.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue
        cleaned = _clean_text(text)
        if _is_meaningful(cleaned):
            return cleaned
    return ""


def default_device_name(index: int) -> str:
    """描述缺失或不可解析时的统一可读名称。"""
    return f"网络设备 {index}"


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
    # 仅用于展示：描述不可解析时为统一默认名，不影响 name/description 的原有语义
    display_name: str = ""

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
        text = (self.display_name or self.description).strip()
        desc = f"  {text}" if text else ""
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
            if name:
                description = decode_device_text(entry.description)
                display_name = description or default_device_name(len(devices) + 1)
                loopback = bool(entry.flags & PCAP_IF_LOOPBACK) or is_loopback_name(name)
                devices.append(
                    Interface(
                        name=name,
                        description=description,
                        is_loopback=loopback,
                        flags=int(entry.flags),
                        display_name=display_name,
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
