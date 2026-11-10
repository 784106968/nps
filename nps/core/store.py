"""包存储：固定容量，超出时从最旧的开始丢弃并计数。

界面模型与单元测试共用这一层，容量语义只在这里定义一次。
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator

from nps.core.packet import Packet

DEFAULT_CAPACITY = 200_000


class PacketStore:
    def __init__(self, capacity: int = DEFAULT_CAPACITY) -> None:
        if capacity <= 0:
            raise ValueError("capacity 必须为正整数")
        self._capacity = capacity
        self._packets: list[Packet] = []
        self._dropped_old = 0
        self._total = 0

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def dropped_old(self) -> int:
        """因容量上限被淘汰的旧包数量。"""
        return self._dropped_old

    @property
    def total_seen(self) -> int:
        """累计接收过的包数（含已淘汰）。"""
        return self._total

    def __len__(self) -> int:
        return len(self._packets)

    def __getitem__(self, index: int) -> Packet:
        return self._packets[index]

    def __iter__(self) -> Iterator[Packet]:
        return iter(self._packets)

    def overflow_for(self, incoming: int) -> int:
        """若再追加 incoming 个包，需要先淘汰多少个。"""
        return max(0, len(self._packets) + incoming - self._capacity)

    def drop_front(self, count: int) -> int:
        if count <= 0:
            return 0
        count = min(count, len(self._packets))
        del self._packets[:count]
        self._dropped_old += count
        return count

    def extend(self, packets: Iterable[Packet]) -> None:
        items = list(packets)
        if not items:
            return
        self._total += len(items)
        self._packets.extend(items)
        # 一次性灌入超过容量时，淘汰发生在同一批内部，不能只依赖 drop_front
        excess = len(self._packets) - self._capacity
        if excess > 0:
            del self._packets[:excess]
            self._dropped_old += excess

    def clear(self) -> None:
        self._packets.clear()
        self._dropped_old = 0
        self._total = 0
