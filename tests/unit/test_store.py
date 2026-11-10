"""定容包存储测试。"""

from __future__ import annotations

import pytest

from nps.core.packet import Packet
from nps.core.store import PacketStore


def make_packet(index: int) -> Packet:
    return Packet(
        index=index,
        ts=0.0,
        caplen=0,
        wirelen=0,
        linktype=1,
        raw=memoryview(b""),
    )


def test_invalid_capacity_rejected() -> None:
    with pytest.raises(ValueError):
        PacketStore(0)


def test_extend_and_index() -> None:
    store = PacketStore(10)
    store.extend([make_packet(i) for i in range(3)])
    assert len(store) == 3
    assert store[1].index == 1
    assert store.total_seen == 3
    assert [packet.index for packet in store] == [0, 1, 2]


def test_overflow_drops_oldest() -> None:
    store = PacketStore(3)
    store.extend([make_packet(i) for i in range(5)])
    assert len(store) == 3
    assert [packet.index for packet in store] == [2, 3, 4]
    assert store.dropped_old == 2
    assert store.total_seen == 5


def test_overflow_for_is_pure_query() -> None:
    store = PacketStore(3)
    store.extend([make_packet(1)])
    assert store.overflow_for(1) == 0
    assert store.overflow_for(3) == 1
    assert len(store) == 1


def test_drop_front_counts() -> None:
    store = PacketStore(10)
    store.extend([make_packet(i) for i in range(4)])
    assert store.drop_front(2) == 2
    assert [packet.index for packet in store] == [2, 3]
    assert store.dropped_old == 2


def test_clear_resets_counters() -> None:
    store = PacketStore(2)
    store.extend([make_packet(i) for i in range(4)])
    store.clear()
    assert len(store) == 0
    assert store.dropped_old == 0
    assert store.total_seen == 0
