"""FakeBackend 测试：CI 中替代真实网卡，保证链路可测。"""

from __future__ import annotations

import pytest

from nps.capture.backend import CaptureConfig, FakeBackend
from nps.core.buffer import BoundedPacketQueue
from nps.core.packet import Packet


def make_packet(index: int) -> Packet:
    return Packet(
        index=index,
        ts=0.0,
        caplen=4,
        wirelen=4,
        linktype=1,
        raw=memoryview(b"\x00\x01\x02\x03"),
    )


def test_start_requires_open() -> None:
    backend = FakeBackend()
    with pytest.raises(RuntimeError):
        backend.start(lambda packet: None)


def test_delivers_fed_packets() -> None:
    backend = FakeBackend()
    backend.open(CaptureConfig(device="fake0"))
    queue = BoundedPacketQueue(100)
    for index in range(3):
        assert backend.feed(make_packet(index)) is True

    backend.start(queue.put)
    try:
        assert backend.wait_delivered(3, timeout=2.0) is True
    finally:
        backend.stop()

    drained = queue.drain(10)
    assert [p.index for p in drained] == [0, 1, 2]


def test_overflow_is_counted() -> None:
    backend = FakeBackend(capacity=1)
    backend.open(CaptureConfig(device="fake0"))
    assert backend.feed(make_packet(1)) is True
    assert backend.feed(make_packet(2)) is False
    assert backend.stats().drop == 1


def test_filter_expression_is_recorded() -> None:
    backend = FakeBackend()
    backend.open(CaptureConfig(device="fake0"))
    backend.set_filter("tcp port 80")
    assert backend.filter_expression == "tcp port 80"


def test_stop_is_idempotent() -> None:
    backend = FakeBackend()
    backend.open(CaptureConfig(device="fake0"))
    backend.start(lambda packet: None)
    backend.stop()
    backend.stop()
    backend.close()
    assert backend.stats().recv == 0


def test_datalink_defaults_to_ethernet() -> None:
    assert FakeBackend().datalink() == 1
