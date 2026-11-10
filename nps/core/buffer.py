"""有界包队列。

捕获回调只做拷贝与入队，队列满时立即丢弃并计数，绝不阻塞捕获线程
（见 NPS-Readme.md §3.1、§3.3）。
"""

from __future__ import annotations

import queue
import threading

from nps.core.packet import Packet

DEFAULT_CAPACITY = 100_000


class BoundedPacketQueue:
    """线程安全的有界队列，暴露丢弃计数。"""

    def __init__(self, maxsize: int = DEFAULT_CAPACITY) -> None:
        if maxsize <= 0:
            raise ValueError("maxsize 必须为正整数")
        self._maxsize = maxsize
        self._queue: queue.Queue[Packet] = queue.Queue(maxsize=maxsize)
        self._lock = threading.Lock()
        self._dropped = 0
        self._accepted = 0

    @property
    def maxsize(self) -> int:
        return self._maxsize

    @property
    def dropped(self) -> int:
        with self._lock:
            return self._dropped

    @property
    def accepted(self) -> int:
        with self._lock:
            return self._accepted

    def qsize(self) -> int:
        return self._queue.qsize()

    def put(self, packet: Packet) -> bool:
        """入队成功返回 True；队列满则丢弃并返回 False。"""
        try:
            self._queue.put_nowait(packet)
        except queue.Full:
            with self._lock:
                self._dropped += 1
            return False
        with self._lock:
            self._accepted += 1
        return True

    def drain(self, max_items: int = 500) -> list[Packet]:
        """批量取出，供 GUI 定时器或 CLI 循环消费。"""
        if max_items <= 0:
            return []
        items: list[Packet] = []
        for _ in range(max_items):
            try:
                items.append(self._queue.get_nowait())
            except queue.Empty:
                break
        return items

    def reset(self) -> None:
        """清空队列并重置计数（用于"清空"动作）。"""
        while True:
            try:
                self._queue.get_nowait()
            except queue.Empty:
                break
        with self._lock:
            self._dropped = 0
            self._accepted = 0
