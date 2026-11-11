"""DPI 与统计视图的界面集成测试。"""

from __future__ import annotations

import os
import socket
import struct

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="未安装 PySide6（pip install -e '.[gui]'）")

from PySide6.QtCore import Qt  # noqa: E402
from PySide6.QtGui import QGuiApplication  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from nps.core.packet import Packet  # noqa: E402
from nps.gui.main_window import MainWindow  # noqa: E402

HTTP_GET = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


def frame(proto: int, payload: bytes, sport: int = 50000, dport: int = 12345) -> bytes:
    transport = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, 0x18, 64240, 0, 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(transport),
        1,
        0x4000,
        64,
        proto,
        0,
        socket.inet_aton("10.0.0.1"),
        socket.inet_aton("10.0.0.2"),
    )
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + transport


def udp_frame(payload: bytes, dport: int = 9999) -> bytes:
    udp = struct.pack("!HHHH", 50001, dport, 8 + len(payload), 0) + payload
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        1,
        0x4000,
        64,
        17,
        0,
        socket.inet_aton("10.0.0.3"),
        socket.inet_aton("10.0.0.4"),
    )
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + udp


def packets() -> list[Packet]:
    frames = [frame(6, HTTP_GET), udp_frame(b"hello")]
    return [
        Packet(
            index=index + 1,
            ts=1_700_000_000.0 + index,
            caplen=len(raw),
            wirelen=len(raw),
            linktype=1,
            raw=memoryview(raw),
        )
        for index, raw in enumerate(frames)
    ]


def test_protocol_column_shows_app_protocol(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(packets())
        label = window.packet_model.data(window.packet_model.index(0, 4))
        assert label == "HTTP"
        assert window.packet_model.data(window.packet_model.index(1, 4)) == "UDP"
    finally:
        window.close()


def test_protocol_tooltip_shows_confidence(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(packets())
        tip = window.packet_model.data(window.packet_model.index(0, 4), Qt.ItemDataRole.ToolTipRole)
        assert "HTTP" in tip and "DPI" in tip
    finally:
        window.close()


def test_detail_tree_has_application_layer(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(packets())
        window.select_row(0)
        count = window.detail_tree.topLevelItemCount()
        assert count == 4
        assert window.detail_tree.topLevelItem(3).text(0).startswith("HTTP")
    finally:
        window.close()


def test_protocol_filter_matches_dpi_label(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(packets())
        assert window.set_display_filter("protocol == http") is True
        assert window.filter_proxy.rowCount() == 1

        # protocol 是"最高层协议"：HTTP 流不会再匹配 tcp，需要用 ip.proto
        window.set_display_filter("protocol == tcp")
        assert window.filter_proxy.rowCount() == 0
        window.set_display_filter("ip.proto == tcp")
        assert window.filter_proxy.rowCount() == 1
    finally:
        window.close()


def test_stats_are_consistent_with_sessions(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(packets())
        window.stats_view.update_from(window.packet_model)

        table = window.stats_view.protocol_table
        assert table.rowCount() >= 2
        names = {table.item(row, 0).text() for row in range(table.rowCount())}
        assert "HTTP" in names

        total_packets = sum(int(table.item(row, 1).text()) for row in range(table.rowCount()))
        session_packets = sum(
            session.packets_total for session in window.packet_model.session_table.sessions()
        )
        assert total_packets == session_packets

        timeline = window.stats_view.timeline
        assert timeline.isVisible() or timeline.height() > 0
    finally:
        window.close()


def test_copy_field_to_clipboard(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(packets())
        window.select_row(0)
        app_layer = window.detail_tree.topLevelItem(3)
        window.detail_tree.setCurrentItem(app_layer)
        window.detail_tree.copy_current(with_name=True)
        text = QGuiApplication.clipboard().text()
        assert text.startswith("HTTP:")
    finally:
        window.close()
