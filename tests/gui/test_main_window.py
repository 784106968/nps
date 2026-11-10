"""GUI 冒烟测试：三窗格结构与联动。

CI 不安装 PySide6（可选依赖），因此整组用例在缺少 Qt 时跳过。
"""

from __future__ import annotations

import os
import struct

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="未安装 PySide6（pip install -e '.[gui]'）")

from PySide6.QtWidgets import QApplication, QSplitter  # noqa: E402

from nps.core.packet import Packet  # noqa: E402
from nps.gui.main_window import MainWindow  # noqa: E402

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


def udp_frame(payload: bytes = b"hello") -> bytes:
    udp = struct.pack("!HHHH", 5000, 5001, 8 + len(payload), 0) + payload
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
        b"\x0a\x00\x00\x01",
        b"\x0a\x00\x00\x02",
    )
    return MAC_B + MAC_A + b"\x08\x00" + ip + udp


def make_packet(index: int, raw: bytes) -> Packet:
    return Packet(
        index=index,
        ts=1_700_000_000.0 + index,
        caplen=len(raw),
        wirelen=len(raw),
        linktype=1,
        raw=memoryview(raw),
    )


def test_three_panes_are_vertically_stacked(app) -> None:
    window = MainWindow()
    try:
        assert window.splitter.count() == 3
        assert window.splitter.orientation() == window.splitter.orientation().Vertical
        assert window.splitter.childrenCollapsible() is False
        titles = [
            window.splitter.widget(i).findChild(type(window.status_label), "paneTitle").text()
            for i in range(3)
        ]
        assert titles == ["Packet List", "Packet Details", "Packet in Binary"]
    finally:
        window.close()


def test_selection_updates_details_and_binary(app) -> None:
    window = MainWindow()
    try:
        packets = [make_packet(1, udp_frame()), make_packet(2, udp_frame(b"world"))]
        window.feed_packets(packets)
        assert window.packet_model.rowCount() == 2

        window.select_row(1)

        assert window.detail_tree.topLevelItemCount() == 3
        assert window.detail_tree.topLevelItem(2).text(0).startswith("User Datagram Protocol")
        assert window.hex_view.data_length == packets[1].caplen
    finally:
        window.close()


def test_field_selection_highlights_bytes(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets([make_packet(1, udp_frame())])
        window.select_row(0)

        udp_layer = window.detail_tree.topLevelItem(2)
        port_item = udp_layer.child(0)
        window.detail_tree.setCurrentItem(port_item)

        start, length = window.hex_view.highlight
        assert (start, length) == (34, 2)
    finally:
        window.close()


def test_clear_resets_all_panes(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets([make_packet(1, udp_frame())])
        window.select_row(0)
        window.clear_packets()
        assert window.packet_model.rowCount() == 0
        assert window.hex_view.data_length == 0
        assert window.detail_tree.topLevelItemCount() == 1
    finally:
        window.close()


def test_splitter_allows_resizing(app) -> None:
    window = MainWindow()
    try:
        splitter = window.splitter
        assert isinstance(splitter, QSplitter)
        assert splitter.handleWidth() > 0
        assert all(size > 0 for size in splitter.sizes())
    finally:
        window.close()
