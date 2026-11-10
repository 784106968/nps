"""libpcap / Npcap 的 ctypes 绑定（新 API）。

调用序列固定为：

    pcap_create -> pcap_set_* -> pcap_activate -> pcap_compile
    -> pcap_setfilter -> pcap_freecode -> pcap_dispatch -> pcap_breakloop -> pcap_close

注意：
- Windows 上 wpcap.dll 的导出函数是 __cdecl，因此统一用 ``ctypes.CDLL`` 而不是 ``WinDLL``；
- 库在**首次使用时才加载**，import 本模块不会因为缺少 libpcap 而失败（CI 需要这一点）；
- ``struct timeval`` 在 Windows 上 ``long`` 为 32 位，必须用 ``c_long``，不能用 ``c_int64``。
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os
import sys
from ctypes import POINTER, Structure, c_char_p, c_int, c_long, c_uint, c_void_p
from pathlib import Path

PCAP_ERRBUF_SIZE = 256
PCAP_NETMASK_UNKNOWN = 0xFFFFFFFF
PCAP_IF_LOOPBACK = 0x00000001

DLT_NULL = 0
DLT_EN10MB = 1
DLT_RAW = 12
DLT_LINUX_SLL = 113
DLT_LINUX_SLL2 = 276

DLT_NAMES: dict[int, str] = {
    DLT_NULL: "DLT_NULL",
    DLT_EN10MB: "DLT_EN10MB",
    DLT_RAW: "DLT_RAW",
    101: "DLT_RAW",
    DLT_LINUX_SLL: "DLT_LINUX_SLL",
    DLT_LINUX_SLL2: "DLT_LINUX_SLL2",
}

# pcap_activate 返回值说明（正数为告警，负数为错误）
ACTIVATE_WARNINGS: dict[int, str] = {
    1: "通用告警",
    2: "设备不支持混杂模式",
    3: "不支持指定的时间戳类型",
}

ACTIVATE_ERRORS: dict[int, str] = {
    -1: "通用错误",
    -2: "循环被中断",
    -3: "句柄尚未激活",
    -4: "句柄已激活",
    -5: "设备不存在或没有权限",
    -6: "设备不支持 RF 监听模式",
    -7: "设备不在 RF 监听模式",
    -8: "权限不足",
    -9: "接口未启用",
    -10: "无法设置时间戳类型",
    -11: "权限不足，无法开启混杂模式",
    -12: "不支持指定的时间戳精度",
}


class PcapError(RuntimeError):
    """libpcap 调用失败。"""


class Timeval(Structure):
    _fields_ = [("tv_sec", c_long), ("tv_usec", c_long)]


class Pkthdr(Structure):
    _fields_ = [("ts", Timeval), ("caplen", c_uint), ("len", c_uint)]


class PcapStat(Structure):
    _fields_ = [("ps_recv", c_uint), ("ps_drop", c_uint), ("ps_ifdrop", c_uint)]


class BpfProgram(Structure):
    _fields_ = [("bf_len", c_uint), ("bf_insns", c_void_p)]


class PcapIf(Structure):
    pass


PcapIf._fields_ = [  # noqa: SLF001 - ctypes 自引用结构体必须后置赋值
    ("next", POINTER(PcapIf)),
    ("name", c_char_p),
    ("description", c_char_p),
    ("addresses", c_void_p),
    ("flags", c_uint),
]


_lib: ctypes.CDLL | None = None


def _candidates() -> tuple[str, ...]:
    if sys.platform == "win32":
        names: list[str] = []
        # 先找 Npcap 的安装目录：System32 下可能残留 2010 年的 WinPcap 4.x，
        # 若直接按裸名加载会被它遮蔽，导致 set_immediate_mode 等新 API 缺失。
        system_root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        npcap = Path(system_root) / "System32" / "Npcap"
        for candidate in (npcap / "wpcap.dll", npcap / "wpcap" / "wpcap.dll"):
            if candidate.exists():
                names.append(str(candidate))
                break
        names.append("wpcap.dll")
        return tuple(names)
    if sys.platform == "darwin":
        return ("libpcap.A.dylib", "libpcap.dylib")
    return ("libpcap.so.1", "libpcap.so.0.8", "libpcap.so")


def _load() -> ctypes.CDLL:
    problems: list[str] = []
    for name in _candidates():
        try:
            return ctypes.CDLL(name)
        except OSError as exc:  # pragma: no cover - 取决于运行环境
            problems.append(f"{name}: {exc}")
    found = ctypes.util.find_library("pcap")
    if found:
        try:
            return ctypes.CDLL(found)
        except OSError as exc:  # pragma: no cover
            problems.append(f"{found}: {exc}")
    detail = "；".join(problems) if problems else "未找到候选库文件"
    raise PcapError(
        "无法加载 libpcap / Npcap。"
        "Windows 请安装 Npcap（勾选 loopback 支持）；"
        f"Linux 请安装 libpcap0.8 / libpcap-dev。详情：{detail}"
    )


def _sig(func: object, argtypes: list[object], restype: object) -> None:
    func.argtypes = argtypes  # type: ignore[attr-defined]
    func.restype = restype  # type: ignore[attr-defined]


def _bind(lib: ctypes.CDLL) -> None:
    _sig(lib.pcap_lib_version, [], c_char_p)
    _sig(lib.pcap_create, [c_char_p, c_char_p], c_void_p)
    _sig(lib.pcap_set_snaplen, [c_void_p, c_int], c_int)
    _sig(lib.pcap_set_promisc, [c_void_p, c_int], c_int)
    _sig(lib.pcap_set_timeout, [c_void_p, c_int], c_int)
    _sig(lib.pcap_set_buffer_size, [c_void_p, c_int], c_int)
    _sig(lib.pcap_activate, [c_void_p], c_int)
    _sig(lib.pcap_geterr, [c_void_p], c_char_p)
    _sig(lib.pcap_datalink, [c_void_p], c_int)
    _sig(lib.pcap_compile, [c_void_p, POINTER(BpfProgram), c_char_p, c_int, c_uint], c_int)
    _sig(lib.pcap_setfilter, [c_void_p, POINTER(BpfProgram)], c_int)
    _sig(lib.pcap_freecode, [POINTER(BpfProgram)], None)
    _sig(lib.pcap_lookupnet, [c_char_p, POINTER(c_uint), POINTER(c_uint), c_char_p], c_int)
    _sig(lib.pcap_dispatch, [c_void_p, c_int, c_void_p, c_void_p], c_int)
    _sig(lib.pcap_breakloop, [c_void_p], None)
    _sig(lib.pcap_stats, [c_void_p, POINTER(PcapStat)], c_int)
    _sig(lib.pcap_close, [c_void_p], None)
    _sig(lib.pcap_open_offline, [c_char_p, c_char_p], c_void_p)
    _sig(
        lib.pcap_findalldevs,
        [POINTER(POINTER(PcapIf)), c_char_p],
        c_int,
    )
    _sig(lib.pcap_freealldevs, [POINTER(PcapIf)], None)

    # 老版本 libpcap 可能没有这些符号，缺失时降级而不是崩溃
    for name, argtypes, restype in (
        ("pcap_set_immediate_mode", [c_void_p, c_int], c_int),
        ("pcap_set_tstamp_precision", [c_void_p, c_int], c_int),
        ("pcap_statustostr", [c_int], c_char_p),
    ):
        func = getattr(lib, name, None)
        if func is not None:
            _sig(func, argtypes, restype)


def load_library(force: bool = False) -> ctypes.CDLL:
    """加载并绑定 libpcap，进程内缓存。"""
    global _lib
    if _lib is not None and not force:
        return _lib
    lib = _load()
    _bind(lib)
    _lib = lib
    return lib


def has_function(name: str) -> bool:
    lib = load_library()
    return hasattr(lib, name)


def _decode(value: bytes | None) -> str:
    if not value:
        return ""
    return value.decode("utf-8", errors="replace")


def errbuf_text(buf: ctypes.Array[ctypes.c_char]) -> str:  # type: ignore[type-arg]
    raw = bytes(buf.value)
    return raw.decode("utf-8", errors="replace")


def error_of(lib: ctypes.CDLL, handle: object, fallback: str = "") -> str:
    """取 pcap_geterr 的错误文本，取不到时回退。"""
    try:
        text = _decode(lib.pcap_geterr(handle))
    except Exception:  # pragma: no cover - 句柄异常时保底
        text = ""
    return text or fallback


def describe_activate(rc: int) -> str:
    if rc < 0:
        return ACTIVATE_ERRORS.get(rc, f"未知错误 {rc}")
    return ACTIVATE_WARNINGS.get(rc, f"未知告警 {rc}")


def version() -> str:
    lib = load_library()
    return _decode(lib.pcap_lib_version()) or "unknown"


def is_legacy_winpcap() -> bool:
    """Windows 上是否加载到了旧的 WinPcap 4.x（缺少新 API）。"""
    try:
        text = version().lower()
    except PcapError:
        return False
    return "winpcap" in text or "libpcap version 1.0" in text


def no_device_hint() -> str:
    if sys.platform == "win32":
        hint = (
            "未枚举到任何网卡。Windows 需要安装 Npcap 驱动（含 npcap 服务），"
            "只有 wpcap.dll 而没有驱动时无法抓包。"
        )
        if is_legacy_winpcap():
            hint += "当前加载的是旧版 WinPcap 库，请安装 Npcap 后重试。"
        return hint
    return "未枚举到任何网卡。请检查 libpcap 安装与权限（/dev/bpf*、CAP_NET_RAW）。"


def status_text(rc: int) -> str:
    """优先使用 libpcap 自带的 pcap_statustostr。"""
    lib = load_library()
    func = getattr(lib, "pcap_statustostr", None)
    if func is not None:
        text = _decode(func(rc))
        if text:
            return text
    return describe_activate(rc)


__all__ = [
    "ACTIVATE_ERRORS",
    "ACTIVATE_WARNINGS",
    "BpfProgram",
    "DLT_EN10MB",
    "DLT_LINUX_SLL",
    "DLT_LINUX_SLL2",
    "DLT_NAMES",
    "DLT_NULL",
    "DLT_RAW",
    "PCAP_ERRBUF_SIZE",
    "PCAP_IF_LOOPBACK",
    "PCAP_NETMASK_UNKNOWN",
    "PcapError",
    "PcapIf",
    "PcapStat",
    "Pkthdr",
    "Timeval",
    "describe_activate",
    "errbuf_text",
    "error_of",
    "has_function",
    "is_legacy_winpcap",
    "load_library",
    "no_device_hint",
    "status_text",
    "version",
]
