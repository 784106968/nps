"""会话面板与同流高亮的界面测试。"""

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
from nps.gui.main_window import MainWindow  # noqa: E402

CLIENT = ("10.0.0.1", 51234)
SERVER = ("93.184.216.34", 80)


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


def tcp_frame(
    src: tuple[str, int], dst: tuple[str, int], flags: int, payload: bytes = b""
) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], 1, 0, 0x50, flags, 64240, 0, 0) + payload
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
        socket.inet_aton(src[0]),
        socket.inet_aton(dst[0]),
    )
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp


def packet(frame: bytes, index: int, ts: float) -> Packet:
    return Packet(
        index=index,
        ts=ts,
        caplen=len(frame),
        wirelen=len(frame),
        linktype=1,
        raw=memoryview(frame),
    )


def handshake() -> list[Packet]:
    frames = [
        tcp_frame(CLIENT, SERVER, 0x02),
        tcp_frame(SERVER, CLIENT, 0x12),
        tcp_frame(CLIENT, SERVER, 0x10),
        tcp_frame(CLIENT, SERVER, 0x18, b"GET / HTTP/1.1\r\n"),
        tcp_frame(SERVER, CLIENT, 0x18, b"HTTP/1.1 200 OK\r\n"),
        tcp_frame(CLIENT, SERVER, 0x11),
    ]
    return [packet(frame, index + 1, 1_000.0 + index * 0.01) for index, frame in enumerate(frames)]


def test_handshake_becomes_single_session(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(handshake())
        assert window.session_model.rowCount() == 1
        session = window.session_model.session_at(0)
        assert session is not None
        assert session.packets_total == 6
        assert session.packets_up == 4
        assert session.packets_down == 2
    finally:
        window.close()


def test_selecting_packet_highlights_whole_stream(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(handshake())
        window.select_row(3)

        for row in range(window.packet_model.rowCount()):
            color = window.packet_model.data(
                window.packet_model.index(row, 0), Qt.ItemDataRole.BackgroundRole
            )
            assert color is not None, f"第 {row} 行没有被高亮"
    finally:
        window.close()


def test_session_click_selects_in_dock(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(handshake())
        window.select_row(2)
        current = window.session_view.currentIndex()
        assert current.isValid()
        assert current.row() == 0
    finally:
        window.close()


def test_double_click_jumps_to_first_packet(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(handshake())
        window.select_row(5)
        window._on_session_activated(window.session_model.index(0, 0))
        assert window.table.currentIndex().row() == 0
    finally:
        window.close()


def test_process_column_is_placeholder(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(handshake())
        value = window.session_model.data(window.session_model.index(0, 7))
        assert value == "—"
    finally:
        window.close()


def test_clear_resets_sessions(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(handshake())
        window.clear_packets()
        assert window.session_model.rowCount() == 0
        assert len(window.packet_model.session_table) == 0
    finally:
        window.close()
