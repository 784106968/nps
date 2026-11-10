"""显示过滤器与界面的集成测试。"""

from __future__ import annotations

import os
import struct

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="未安装 PySide6（pip install -e '.[gui]'）")

from PySide6.QtWidgets import QApplication  # noqa: E402

from nps.core.packet import Packet  # noqa: E402
from nps.gui.main_window import MainWindow  # noqa: E402

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


def ipv4(payload: bytes, proto: int) -> bytes:
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(payload),
        1,
        0x4000,
        64,
        proto,
        0,
        b"\x0a\x00\x00\x01",
        b"\x0a\x00\x00\x02",
    )


def udp_frame(dport: int = 5001) -> bytes:
    udp = struct.pack("!HHHH", 5000, dport, 9, 0) + b"x"
    return MAC_B + MAC_A + b"\x08\x00" + ipv4(udp, 17)


def icmp_frame() -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping"
    return MAC_B + MAC_A + b"\x08\x00" + ipv4(body, 1)


def packets() -> list[Packet]:
    frames = [udp_frame(), icmp_frame(), udp_frame(5002)]
    return [
        Packet(
            index=index + 1,
            ts=1_700_000_000.0 + index,
            caplen=len(frame),
            wirelen=len(frame),
            linktype=1,
            raw=memoryview(frame),
        )
        for index, frame in enumerate(frames)
    ]


def make_window(app) -> MainWindow:
    window = MainWindow()
    window.feed_packets(packets())
    return window


def test_filter_hides_rows_without_dropping_them(app) -> None:
    window = make_window(app)
    try:
        assert window.filter_proxy.rowCount() == 3
        assert window.set_display_filter("protocol == icmp") is True
        assert window.filter_proxy.rowCount() == 1
        assert window.packet_model.rowCount() == 3  # 数据仍在，只是不可见
    finally:
        window.close()


def test_clearing_filter_restores_rows(app) -> None:
    window = make_window(app)
    try:
        window.set_display_filter("protocol == icmp")
        assert window.filter_proxy.rowCount() == 1
        window.set_display_filter("")
        assert window.filter_proxy.rowCount() == 3
    finally:
        window.close()


def test_invalid_filter_keeps_previous_and_shows_error(app) -> None:
    window = make_window(app)
    try:
        window.set_display_filter("protocol == icmp")
        assert window.set_display_filter("ip.srcc == 1") is False
        assert window.filter_error_label.text().startswith("×")
        assert window.filter_proxy.rowCount() == 1  # 上一条有效规则仍生效
        assert "过滤表达式无效" in window.status_label.text()
    finally:
        window.close()


def test_hidden_row_cannot_be_selected(app) -> None:
    window = make_window(app)
    try:
        window.set_display_filter("protocol == icmp")
        assert window.select_row(0) is False  # 第 1 行是 UDP，已被过滤
        assert window.select_row(1) is True
    finally:
        window.close()


def test_selection_links_through_proxy(app) -> None:
    window = make_window(app)
    try:
        window.set_display_filter("protocol == icmp")
        assert window.select_row(1) is True
        assert window.detail_tree.topLevelItem(2).text(0).startswith("ICMP")
        assert window.hex_view.data_length > 0
    finally:
        window.close()


def test_filter_status_shows_both_counts(app) -> None:
    window = make_window(app)
    try:
        window.set_display_filter("protocol == icmp")
        text = window.count_label.text()
        assert "3" in text and "1" in text
    finally:
        window.close()
