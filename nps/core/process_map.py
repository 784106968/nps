"""进程归属：把本机会话映射到产生它的进程（P6，Windows 优先）。

实现范围：

- **Windows**：``GetExtendedTcpTable`` / ``GetExtendedUdpTable`` 读取连接与 owner PID，
  ``QueryFullProcessImageNameW`` 读取进程名；全部走 ctypes，保持零第三方依赖；
- **Linux**：本期搁置，``create_resolver`` 回退到 ``NullResolver``，
  方案保留在 ``docs/PROCESS_ATTRIBUTION.md`` §4。

调用约束：

- 只在**会话创建**与**首个载荷到达**时查询，绝不在每包路径调用 OS；
- 连接快照按 TTL（默认 2 s）惰性刷新，进程名缓存 30 s；
- 任何异常都降级为 ``None``，不向捕获/界面线程抛栈。
"""

from __future__ import annotations

import ctypes
import socket
import struct
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol, runtime_checkable

DEFAULT_TTL = 2.0
NAME_TTL = 30.0
MAX_TABLE_SIZE = 16 * 1024 * 1024

AF_INET = 2
AF_INET6 = 23
TCP_TABLE_OWNER_PID_ALL = 5
UDP_TABLE_OWNER_PID = 1
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

TCP4_FMT = "<6I"
TCP6_FMT = "<16sII16sIIII"
UDP4_FMT = "<3I"
UDP6_FMT = "<16sIII"
TCP4_SIZE = struct.calcsize(TCP4_FMT)
TCP6_SIZE = struct.calcsize(TCP6_FMT)
UDP4_SIZE = struct.calcsize(UDP4_FMT)
UDP6_SIZE = struct.calcsize(UDP6_FMT)

WILDCARD_ADDRS = {"0.0.0.0", "::"}


@dataclass(frozen=True, slots=True)
class ProcessInfo:
    """一次归属结果；``confidence`` 明确标注依据，界面不得把它说成确定结论。"""

    pid: int | None
    name: str
    confidence: str  # "exact" | "port" | "ambiguous"
    note: str = ""


@runtime_checkable
class ProcessResolver(Protocol):
    """把 (本地端点, 远端端点, 协议) 解析为进程。"""

    @property
    def status_text(self) -> str: ...

    def resolve(
        self, local: tuple[str, int], remote: tuple[str, int], proto: int
    ) -> ProcessInfo | None: ...


@dataclass(slots=True)
class ProcessTable:
    """连接表快照 + 匹配规则；与平台无关，便于单元测试。"""

    exact: dict[tuple[int, str, int, str, int], ProcessInfo] = field(default_factory=dict)
    by_port: dict[tuple[int, int], dict[int, ProcessInfo]] = field(default_factory=dict)
    local_addrs: set[str] = field(default_factory=set)

    def __len__(self) -> int:
        return len(self.exact)

    def add(
        self,
        proto: int,
        local: tuple[str, int],
        remote: tuple[str, int],
        pid: int,
    ) -> None:
        local_ip, local_port = local
        remote_ip, remote_port = remote
        if local_ip not in WILDCARD_ADDRS:
            self.local_addrs.add(local_ip)
        if remote_ip not in WILDCARD_ADDRS and remote_port:
            self.exact[(proto, local_ip, local_port, remote_ip, remote_port)] = ProcessInfo(
                pid, "", "exact"
            )
        self.by_port.setdefault((proto, local_port), {})[pid] = ProcessInfo(
            pid, "", "port", "仅按本地端口匹配"
        )

    def match(
        self, local: tuple[str, int], remote: tuple[str, int], proto: int
    ) -> ProcessInfo | None:
        local_ip, local_port = local
        remote_ip, remote_port = remote
        local_is_local = local_ip in self.local_addrs
        remote_is_local = remote_ip in self.local_addrs

        if local_is_local:
            info = self.exact.get((proto, local_ip, local_port, remote_ip, remote_port))
            if info is not None:
                return info
        if remote_is_local:
            info = self.exact.get((proto, remote_ip, remote_port, local_ip, local_port))
            if info is not None:
                return info
        if not local_is_local and not remote_is_local:
            # 抓镜像口/SPAN 时两端都不在本机地址表，宁可不归属
            return None

        endpoint_port = local_port if local_is_local else remote_port
        candidates = self.by_port.get((proto, endpoint_port))
        if not candidates:
            return None
        if len(candidates) == 1:
            return next(iter(candidates.values()))
        return ProcessInfo(
            None,
            "",
            "ambiguous",
            f"本地端口 {endpoint_port} 被多个进程共用，已放弃归属",
        )


class NullResolver:
    """空实现：非 Windows 平台或初始化失败时使用。"""

    status_text = "不可用（当前平台暂未实现）"

    def resolve(
        self, local: tuple[str, int], remote: tuple[str, int], proto: int
    ) -> ProcessInfo | None:
        return None


# ---- Windows 表读取 ----
def _ipv4(value: int) -> str:
    return socket.inet_ntoa(struct.pack("<I", value))


def _port(value: int) -> int:
    return socket.ntohs(value & 0xFFFF)


def _ipv6(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, raw)


def _query_table(af: int, table_class: int, function: str) -> bytes:
    """调用 GetExtended*Table，返回从 dwNumEntries 开始的原始缓冲。"""
    if sys.platform != "win32":  # pragma: no cover - 仅 Windows 可达
        raise OSError("进程归属当前仅支持 Windows")

    iphlpapi = ctypes.WinDLL("iphlpapi.dll")
    getter = getattr(iphlpapi, function)
    getter.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_ulong),
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_int,
        ctypes.c_ulong,
    ]
    getter.restype = ctypes.c_ulong

    size = ctypes.c_ulong(0)
    getter(None, ctypes.byref(size), False, af, table_class, 0)
    if size.value == 0:
        return b""
    if size.value > MAX_TABLE_SIZE:
        raise OSError(f"{function} 返回异常表大小 {size.value}")
    buffer = ctypes.create_string_buffer(size.value)
    code = getter(buffer, ctypes.byref(size), False, af, table_class, 0)
    if code != 0:
        raise OSError(f"{function} 失败，错误码 {code}")
    return bytes(buffer.raw[: size.value])


def _windows_table() -> ProcessTable:
    table = ProcessTable()
    tcp_specs = (
        (AF_INET, TCP4_FMT, TCP4_SIZE, "GetExtendedTcpTable"),
        (AF_INET6, TCP6_FMT, TCP6_SIZE, "GetExtendedTcpTable"),
    )
    for af, fmt, size, function in tcp_specs:
        raw = _query_table(af, TCP_TABLE_OWNER_PID_ALL, function)
        if not raw:
            continue
        count = struct.unpack_from("<I", raw, 0)[0]
        for index in range(count):
            row = struct.unpack_from(fmt, raw, 4 + index * size)
            if af == AF_INET:
                _, local_addr, local_port, remote_addr, remote_port, pid = row
                table.add(
                    6,
                    (_ipv4(local_addr), _port(local_port)),
                    (_ipv4(remote_addr), _port(remote_port)),
                    int(pid),
                )
            else:
                local_addr, _, local_port, remote_addr, _, remote_port, _, pid = row
                table.add(
                    6,
                    (_ipv6(local_addr), _port(local_port)),
                    (_ipv6(remote_addr), _port(remote_port)),
                    int(pid),
                )

    udp_specs = (
        (AF_INET, UDP4_FMT, UDP4_SIZE, "GetExtendedUdpTable"),
        (AF_INET6, UDP6_FMT, UDP6_SIZE, "GetExtendedUdpTable"),
    )
    for af, fmt, size, function in udp_specs:
        raw = _query_table(af, UDP_TABLE_OWNER_PID, function)
        if not raw:
            continue
        count = struct.unpack_from("<I", raw, 0)[0]
        for index in range(count):
            row = struct.unpack_from(fmt, raw, 4 + index * size)
            if af == AF_INET:
                local_addr, local_port, pid = row
                table.add(
                    17,
                    (_ipv4(local_addr), _port(local_port)),
                    ("0.0.0.0", 0),
                    int(pid),
                )
            else:
                local_addr, _, local_port, pid = row
                table.add(
                    17,
                    (_ipv6(local_addr), _port(local_port)),
                    ("::", 0),
                    int(pid),
                )
    return table


def _windows_process_name(pid: int) -> str:
    if pid == 0:
        return "System Idle Process"
    if pid == 4:
        return "System"
    kernel32 = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        size = ctypes.c_ulong(1024)
        buffer = ctypes.create_unicode_buffer(size.value)
        if kernel32.QueryFullProcessImageNameW(handle, 0, buffer, ctypes.byref(size)):
            return Path(buffer.value).name
    finally:
        kernel32.CloseHandle(handle)
    return ""


class SystemResolver:
    """带 TTL 快照与名称缓存的解析器；构造不触发任何 OS 调用。"""

    def __init__(
        self,
        loader: Callable[[], ProcessTable] | None = None,
        clock: Callable[[], float] = time.monotonic,
        ttl: float = DEFAULT_TTL,
    ) -> None:
        self._loader = loader or _windows_table
        self._clock = clock
        self._ttl = ttl
        self._table: ProcessTable | None = None
        self._created = 0.0
        self._names: dict[int, tuple[float, str]] = {}
        self._lock = threading.Lock()
        self._note = ""
        self._last_refresh_ms = 0.0

    @property
    def status_text(self) -> str:
        if self._note:
            return f"不可用（{self._note}）"
        if self._table is None:
            return "正在初始化"
        return f"可用（{len(self._table)} 条连接）"

    @property
    def last_refresh_ms(self) -> float:
        return self._last_refresh_ms

    @property
    def table(self) -> ProcessTable | None:
        """最近一次快照（只读，供 probe/测试查看）。"""
        return self._table

    def refresh(self, force: bool = False) -> None:
        now = self._clock()
        with self._lock:
            if self._table is not None and not force and now - self._created < self._ttl:
                return
            started = time.perf_counter()
            try:
                table = self._loader()
            except Exception as exc:  # 权限/API 异常一律降级，不打断抓包
                self._note = f"读取失败：{exc}"
                self._last_refresh_ms = (time.perf_counter() - started) * 1000.0
                return
            self._table = table
            self._created = now
            self._note = ""
            self._last_refresh_ms = (time.perf_counter() - started) * 1000.0

    def resolve(
        self, local: tuple[str, int], remote: tuple[str, int], proto: int
    ) -> ProcessInfo | None:
        self.refresh()
        table = self._table
        if table is None:
            return None
        info = table.match(local, remote, proto)
        if info is None or info.pid is None:
            return info
        name = self._name_for(info.pid)
        note = info.note
        if not name and not note:
            note = "无法读取进程名（权限不足或进程已退出）"
        return ProcessInfo(info.pid, name, info.confidence, note)

    def _name_for(self, pid: int) -> str:
        now = self._clock()
        cached = self._names.get(pid)
        if cached is not None and now - cached[0] < NAME_TTL:
            return cached[1]
        name = _windows_process_name(pid)
        self._names[pid] = (now, name)
        return name


def create_resolver() -> ProcessResolver:
    """按平台创建解析器；本期只有 Windows 实现，其他平台返回空实现。"""
    if sys.platform == "win32":
        try:
            return SystemResolver()
        except Exception:  # pragma: no cover - 极端环境兜底
            return NullResolver()
    return NullResolver()


__all__ = [
    "NullResolver",
    "ProcessInfo",
    "ProcessResolver",
    "ProcessTable",
    "SystemResolver",
    "create_resolver",
]
