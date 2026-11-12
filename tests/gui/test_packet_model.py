"""审查修复回归：容量淘汰后的流索引、超容量插入、队列清空与过滤重算。"""

from __future__ import annotations

import os
import socket
import struct

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="未安装 PySide6（pip install -e '.[gui]'）")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from nps.core.packet import Packet  # noqa: E402
from nps.gui.flow_view import FlowView  # noqa: E402
from nps.gui.main_window import MainWindow  # noqa: E402
from nps.gui.packet_model import PacketTableModel  # noqa: E402

_seq = 0


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


def tcp_packet(sport: int, dport: int, ts: float) -> Packet:
    global _seq
    _seq += 1
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x10, 64240, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0x4000,
        64,
        6,
        0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton("93.184.216.34"),
    )
    frame = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp
    return Packet(
        index=_seq,
        ts=ts,
        caplen=len(frame),
        wirelen=len(frame),
        linktype=1,
        raw=memoryview(frame),
    )


def test_packets_of_stream_survives_capacity_eviction(app) -> None:
    model = PacketTableModel(capacity=4)
    packets = [tcp_packet(50000, 80, 1_000.0 + index * 0.1) for index in range(6)]
    model.append_batch(packets)

    assert model.rowCount() == 4
    stream_id = packets[-1].stream_id
    assert stream_id is not None
    kept = model.packets_of_stream(stream_id)
    assert [packet.index for packet in kept] == [packet.index for packet in packets[-4:]]
    assert model.row_of_stream(stream_id) == 0


def test_append_batch_larger_than_capacity_does_not_raise(app) -> None:
    model = PacketTableModel(capacity=4)
    model.append_batch([tcp_packet(50000 + index, 80, 1_000.0 + index) for index in range(10)])

    assert model.rowCount() == 4
    stream_id = model.packet_at(0).stream_id
    assert len(model.packets_of_stream(stream_id)) == 1


def test_clear_resets_pending_queue(app) -> None:
    window = MainWindow()
    try:
        window._queue.put(tcp_packet(50000, 80, 1_000.0))
        window.clear_packets()
        assert window._queue.qsize() == 0
    finally:
        window.close()


def test_filter_recomputes_after_session_update(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets([tcp_packet(50000, 80, 1_000.0)])
        assert window.set_display_filter("process.pid == 1234")
        assert window.filter_proxy.rowCount() == 0

        session = window.session_model.session_at(0)
        assert session is not None
        session.pid = 1234
        session.process_confidence = "exact"
        window.packet_model.session_table._version += 1
        window._on_session_tick()

        assert window.filter_proxy.rowCount() == 1
    finally:
        window.close()


def test_flow_view_accepts_keyboard_focus(app) -> None:
    view = FlowView()
    assert view.focusPolicy() == Qt.FocusPolicy.StrongFocus
