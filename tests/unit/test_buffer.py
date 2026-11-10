"""有界队列测试：顺序、容量、丢弃计数。"""

from __future__ import annotations

import pytest

from nps.core.buffer import BoundedPacketQueue
from nps.core.packet import Packet


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
        BoundedPacketQueue(0)


def test_drain_preserves_order() -> None:
    queue = BoundedPacketQueue(10)
    for index in range(5):
        assert queue.put(make_packet(index)) is True
    drained = queue.drain(10)
    assert [p.index for p in drained] == [0, 1, 2, 3, 4]
    assert queue.qsize() == 0


def test_drain_limited_by_max_items() -> None:
    queue = BoundedPacketQueue(10)
    for index in range(5):
        queue.put(make_packet(index))
    assert len(queue.drain(2)) == 2
    assert queue.qsize() == 3


def test_overflow_drops_and_counts() -> None:
    queue = BoundedPacketQueue(2)
    assert queue.put(make_packet(1)) is True
    assert queue.put(make_packet(2)) is True
    assert queue.put(make_packet(3)) is False
    assert queue.dropped == 1
    assert queue.accepted == 2


def test_drain_zero_returns_empty() -> None:
    queue = BoundedPacketQueue(2)
    queue.put(make_packet(1))
    assert queue.drain(0) == []


def test_reset_clears_queue_and_counters() -> None:
    queue = BoundedPacketQueue(1)
    queue.put(make_packet(1))
    queue.put(make_packet(2))
    queue.reset()
    assert queue.qsize() == 0
    assert queue.dropped == 0
    assert queue.accepted == 0
