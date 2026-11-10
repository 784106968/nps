"""捕获后端契约与测试替身。

``CaptureBackend`` 是 GUI、CLI 与测试共同依赖的边界；``FakeBackend`` 让整条链路
（回调 -> 队列 -> 消费）在**没有 Npcap / libpcap 的环境**下也能跑通，CI 因此可以
覆盖捕获路径（见 NPS-Readme.md §6）。
"""

from __future__ import annotations

import queue
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from nps.core.packet import Packet

PacketHandler = Callable[[Packet], None]

DEFAULT_SNAPLEN = 65535
DEFAULT_TIMEOUT_MS = 100
DEFAULT_BUFFER_SIZE = 8 * 1024 * 1024


@dataclass(frozen=True, slots=True)
class CaptureConfig:
    """打开设备时的参数，语义与 libpcap 一致。"""

    device: str
    snaplen: int = DEFAULT_SNAPLEN
    promisc: bool = True
    timeout_ms: int = DEFAULT_TIMEOUT_MS
    buffer_size: int = DEFAULT_BUFFER_SIZE
    immediate: bool = False

    def __post_init__(self) -> None:
        if not self.device:
            raise ValueError("device 不能为空")
        if self.snaplen <= 0:
            raise ValueError("snaplen 必须为正整数")
        if self.timeout_ms <= 0:
            raise ValueError("timeout_ms 必须为正整数（影响停止时延）")
        if self.buffer_size <= 0:
            raise ValueError("buffer_size 必须为正整数")


@dataclass(slots=True)
class CaptureStats:
    """内核统计与用户态队列丢弃必须分开记录，二者语义不同。"""

    recv: int = 0
    drop: int = 0
    ifdrop: int = 0
    queue_dropped: int = 0

    @property
    def kernel_total(self) -> int:
        return self.recv + self.drop + self.ifdrop


@runtime_checkable
class CaptureBackend(Protocol):
    """所有后端（真实 / 伪造 / 离线）必须实现的接口。"""

    def open(self, config: CaptureConfig) -> None: ...

    def set_filter(self, expression: str) -> None: ...

    def start(self, handler: PacketHandler) -> None: ...

    def stop(self) -> None: ...

    def close(self) -> None: ...

    def stats(self) -> CaptureStats: ...

    def datalink(self) -> int: ...


class FakeBackend:
    """内存后端：喂包即可驱动全链路，用于单元测试与 CI。"""

    def __init__(self, capacity: int = 10_000) -> None:
        self._capacity = capacity
        self._queue: queue.Queue[Packet] = queue.Queue(maxsize=capacity)
        self._config: CaptureConfig | None = None
        self._handler: PacketHandler | None = None
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._dropped = 0
        self._delivered = 0
        self._expression: str | None = None
        self._opened = False

    # ---- CaptureBackend ----
    def open(self, config: CaptureConfig) -> None:
        self._config = config
        self._opened = True

    def set_filter(self, expression: str) -> None:
        self._expression = expression

    def start(self, handler: PacketHandler) -> None:
        if not self._opened:
            raise RuntimeError("FakeBackend 未 open 就 start")
        self._handler = handler
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="fake-capture", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=2.0)
            self._thread = None

    def close(self) -> None:
        self.stop()
        self._handler = None
        self._opened = False

    def stats(self) -> CaptureStats:
        with self._lock:
            return CaptureStats(recv=self._delivered, drop=self._dropped)

    def datalink(self) -> int:
        return 1  # DLT_EN10MB

    # ---- 测试辅助 ----
    @property
    def filter_expression(self) -> str | None:
        return self._expression

    def feed(self, packet: Packet) -> bool:
        try:
            self._queue.put_nowait(packet)
        except queue.Full:
            with self._lock:
                self._dropped += 1
            return False
        return True

    def wait_delivered(self, count: int, timeout: float = 2.0) -> bool:
        """等待至少 count 个包被投递（测试用）。"""
        deadline = timeout
        step = 0.01
        waited = 0.0
        while waited < deadline:
            with self._lock:
                if self._delivered >= count:
                    return True
            threading.Event().wait(step)
            waited += step
        with self._lock:
            return self._delivered >= count

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                packet = self._queue.get(timeout=0.05)
            except queue.Empty:
                continue
            handler = self._handler
            if handler is None:
                continue
            handler(packet)
            with self._lock:
                self._delivered += 1
