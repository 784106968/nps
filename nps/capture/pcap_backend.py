"""基于 libpcap 新 API 的捕获后端。

调用序列见 NPS-Readme.md §3.1；本模块只负责"取到包并投递"，解析与界面在更上层。
停止机制刻意使用 ``timeout + pcap_dispatch 轮询 + pcap_breakloop``：Windows 上
``pcap_breakloop`` 不能立即唤醒阻塞中的捕获循环，只有配合短超时才能保证停止时延。
"""

from __future__ import annotations

import contextlib
import ctypes
import threading
from ctypes import POINTER, byref, c_ubyte, c_uint, create_string_buffer

from nps.capture.backend import CaptureConfig, CaptureStats, PacketHandler
from nps.capture.interface import is_loopback_name
from nps.capture.libpcap import (
    PCAP_ERRBUF_SIZE,
    PCAP_NETMASK_UNKNOWN,
    BpfProgram,
    PcapError,
    PcapStat,
    Pkthdr,
    errbuf_text,
    error_of,
    load_library,
    status_text,
)
from nps.core.packet import Packet

CAPTURE_CALLBACK = ctypes.CFUNCTYPE(
    None,
    POINTER(c_ubyte),  # user 指针
    POINTER(Pkthdr),  # pcap_pkthdr
    POINTER(c_ubyte),  # 包数据
)

DISPATCH_BATCH = 64
STOP_TIMEOUT_S = 2.0


class PcapBackend:
    """真实设备后端。"""

    def __init__(self) -> None:
        self._lib: ctypes.CDLL | None = None
        self._handle: ctypes.c_void_p | None = None
        self._config: CaptureConfig | None = None
        self._handler: PacketHandler | None = None
        self._callback: object | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._datalink = 1
        self._packet_index = 0
        self._callback_errors = 0
        self._last_error: str | None = None
        self._warning: str | None = None
        self._notes: list[str] = []
        self._filter_expression: str | None = None
        self._snapshot = CaptureStats()
        self._offline = False
        self._path: str | None = None

    # ---- 生命周期 ----
    def open_offline(self, path: str) -> None:
        """打开离线 PCAP；与在线抓包共用同一套回调与分发逻辑，便于验证与回放。"""
        if self._handle is not None:
            raise PcapError("句柄已打开，请先 close()")
        lib = load_library()
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = lib.pcap_open_offline(str(path).encode("utf-8"), errbuf)
        if not handle:
            raise PcapError(f"打开 PCAP 失败：{errbuf_text(errbuf) or path}")
        self._lib = lib
        self._handle = handle
        self._offline = True
        self._path = str(path)
        self._config = CaptureConfig(device=f"offline:{path}")
        self._datalink = int(lib.pcap_datalink(handle))

    def open(self, config: CaptureConfig) -> None:
        if self._handle is not None:
            raise PcapError("设备已打开，请先 close()")
        lib = load_library()
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        handle = lib.pcap_create(config.device.encode("utf-8"), errbuf)
        if not handle:
            raise PcapError(f"pcap_create 失败：{errbuf_text(errbuf) or '未知原因'}")
        try:
            self._apply_settings(lib, handle, config)
            rc = lib.pcap_activate(handle)
            if rc < 0:
                reason = status_text(rc)
                detail = error_of(lib, handle)
                raise PcapError(f"pcap_activate 失败（{rc} {reason}）：{detail}")
            if rc > 0:
                self._warning = status_text(rc)
            self._lib = lib
            self._handle = handle
            self._config = config
            self._datalink = int(lib.pcap_datalink(handle))
        except Exception:
            lib.pcap_close(handle)
            raise

    def _apply_settings(self, lib: ctypes.CDLL, handle: object, config: CaptureConfig) -> None:
        steps: list[tuple[str, int]] = [
            ("pcap_set_snaplen", config.snaplen),
            ("pcap_set_timeout", config.timeout_ms),
            ("pcap_set_buffer_size", config.buffer_size),
        ]
        if config.promisc:
            if is_loopback_name(config.device) or config.device.strip().lower() == "any":
                self._notes.append("回环/伪设备不支持混杂模式，已跳过 pcap_set_promisc")
            else:
                steps.insert(1, ("pcap_set_promisc", 1))

        for name, value in steps:
            func = getattr(lib, name)
            rc = func(handle, value)
            if rc != 0:
                detail = error_of(lib, handle, f"返回码 {rc}")
                raise PcapError(f"{name}({value}) 失败：{detail}")

        if config.immediate:
            func = getattr(lib, "pcap_set_immediate_mode", None)
            if func is None:
                self._notes.append("当前 libpcap 不支持 immediate mode，已忽略")
            elif func(handle, 1) != 0:
                detail = error_of(lib, handle, "未知原因")
                raise PcapError(f"pcap_set_immediate_mode 失败：{detail}")

    def set_filter(self, expression: str) -> None:
        self._require_open()
        expr = expression.strip()
        if not expr:
            return
        lib = self._lib
        handle = self._handle
        assert lib is not None and handle is not None
        program = BpfProgram()
        rc = lib.pcap_compile(handle, byref(program), expr.encode("utf-8"), 1, self._netmask())
        if rc < 0:
            detail = error_of(lib, handle, "语法错误")
            raise PcapError(f'过滤器 "{expr}" 编译失败：{detail}')
        try:
            rc = lib.pcap_setfilter(handle, byref(program))
        finally:
            lib.pcap_freecode(byref(program))
        if rc < 0:
            detail = error_of(lib, handle, "应用失败")
            raise PcapError(f'过滤器 "{expr}" 应用失败：{detail}')
        self._filter_expression = expr

    def _netmask(self) -> int:
        lib, handle, config = self._lib, self._handle, self._config
        assert lib is not None and handle is not None and config is not None
        if self._offline:
            return PCAP_NETMASK_UNKNOWN
        net = c_uint(0)
        mask = c_uint(0)
        errbuf = create_string_buffer(PCAP_ERRBUF_SIZE)
        if lib.pcap_lookupnet(config.device.encode("utf-8"), byref(net), byref(mask), errbuf) == 0:
            return int(mask.value)
        return PCAP_NETMASK_UNKNOWN

    def start(self, handler: PacketHandler) -> None:
        self._require_open()
        if self._thread is not None:
            raise PcapError("捕获已在运行")
        self._handler = handler
        self._stop.clear()
        # 回调对象必须保持强引用，被 GC 回收后再回调会直接崩溃
        self._callback = CAPTURE_CALLBACK(self._on_packet)
        self._thread = threading.Thread(target=self._loop, name="nps-capture", daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        lib, handle, callback = self._lib, self._handle, self._callback
        assert lib is not None and handle is not None and callback is not None
        while not self._stop.is_set():
            rc = lib.pcap_dispatch(handle, DISPATCH_BATCH, callback, None)
            if rc < 0:
                if rc == -2:  # pcap_breakloop 的正常返回
                    break
                self._last_error = error_of(lib, handle, f"pcap_dispatch 返回 {rc}")
                break
            if rc == 0:
                if self._offline:
                    break  # 离线文件读到 EOF：pcap_dispatch 返回 0，必须主动结束
                continue  # 在线抓包：0 表示超时，继续轮询

    def stop(self) -> None:
        self._stop.set()
        lib, handle = self._lib, self._handle
        if lib is not None and handle is not None:
            lib.pcap_breakloop(handle)
        thread = self._thread
        if thread is not None:
            thread.join(timeout=STOP_TIMEOUT_S)
            self._thread = None
        self._handler = None

    def close(self) -> None:
        self.stop()
        if self._handle is not None:
            # 关闭前抓一次快照，close 之后仍能回答 stats()
            with contextlib.suppress(PcapError):
                self._snapshot = self._read_stats()
            if self._lib is not None:
                self._lib.pcap_close(self._handle)
        self._handle = None
        self._callback = None
        self._config = None
        self._offline = False
        self._path = None

    # ---- 回调 ----
    def _on_packet(self, user: object, header: object, data: object) -> None:
        try:
            hdr = header.contents  # type: ignore[attr-defined]
            raw = ctypes.string_at(data, hdr.caplen)
            self._packet_index += 1
            packet = Packet(
                index=self._packet_index,
                ts=hdr.ts.tv_sec + hdr.ts.tv_usec / 1_000_000.0,
                caplen=int(hdr.caplen),
                wirelen=int(hdr.len),
                linktype=self._datalink,
                raw=memoryview(raw),
            )
            handler = self._handler
            if handler is not None:
                handler(packet)
        except Exception:  # 回调里抛异常会被 C 层吞掉，必须自己计数
            self._callback_errors += 1

    # ---- 查询 ----
    def stats(self) -> CaptureStats:
        if self._handle is None:
            return CaptureStats(
                recv=self._snapshot.recv,
                drop=self._snapshot.drop,
                ifdrop=self._snapshot.ifdrop,
            )
        return self._read_stats()

    def _read_stats(self) -> CaptureStats:
        if self._offline:
            # 离线句柄没有驱动统计，用已投递包数代替
            return CaptureStats(recv=self._packet_index)
        lib, handle = self._lib, self._handle
        assert lib is not None and handle is not None
        stat = PcapStat()
        if lib.pcap_stats(handle, byref(stat)) < 0:
            raise PcapError(f"读取 pcap_stats 失败：{error_of(lib, handle)}")
        return CaptureStats(
            recv=int(stat.ps_recv),
            drop=int(stat.ps_drop),
            ifdrop=int(stat.ps_ifdrop),
        )

    def datalink(self) -> int:
        return self._datalink

    @property
    def is_open(self) -> bool:
        return self._handle is not None

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    @property
    def is_offline(self) -> bool:
        return self._offline

    @property
    def path(self) -> str | None:
        return self._path

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def warning(self) -> str | None:
        return self._warning

    @property
    def notes(self) -> list[str]:
        return list(self._notes)

    @property
    def callback_errors(self) -> int:
        return self._callback_errors

    @property
    def filter_expression(self) -> str | None:
        return self._filter_expression

    def _require_open(self) -> None:
        if self._handle is None:
            raise PcapError("设备未打开")

    def __enter__(self) -> PcapBackend:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
