"""TLS 解析结果在详情树中的展示测试。"""

from __future__ import annotations

import os
import sys

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="未安装 PySide6（pip install -e '.[gui]'）")

from PySide6.QtWidgets import QApplication  # noqa: E402

from nps.core.packet import Packet  # noqa: E402
from nps.gui.main_window import MainWindow  # noqa: E402

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "unit"))
from test_tls import client_hello, tcp_frame  # noqa: E402


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


def make_packet() -> Packet:
    frame = tcp_frame(client_hello())
    return Packet(
        index=1,
        ts=1_700_000_000.0,
        caplen=len(frame),
        wirelen=len(frame),
        linktype=1,
        raw=memoryview(frame),
    )


def texts(item) -> list[str]:
    collected = [item.text(0)]
    for index in range(item.childCount()):
        collected.extend(texts(item.child(index)))
    return collected


def find_item(item, prefix: str):
    if item.text(0).startswith(prefix):
        return item
    for index in range(item.childCount()):
        found = find_item(item.child(index), prefix)
        if found is not None:
            return found
    return None


def test_detail_tree_shows_tls_handshake(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets([make_packet()])
        window.select_row(0)

        titles = [
            window.detail_tree.topLevelItem(index).text(0)
            for index in range(window.detail_tree.topLevelItemCount())
        ]
        assert any(title.startswith("Transport Layer Security") for title in titles)

        tls_item = next(
            window.detail_tree.topLevelItem(index)
            for index in range(window.detail_tree.topLevelItemCount())
            if window.detail_tree.topLevelItem(index).text(0).startswith("Transport Layer Security")
        )
        all_text = texts(tls_item)
        assert any("Client Hello" in text for text in all_text)
        assert any("example.com" in text for text in all_text)
        assert any("http/1.1" in text for text in all_text)
    finally:
        window.close()


def test_selecting_sni_highlights_bytes(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets([make_packet()])
        window.select_row(0)

        tls_item = next(
            window.detail_tree.topLevelItem(index)
            for index in range(window.detail_tree.topLevelItemCount())
            if window.detail_tree.topLevelItem(index).text(0).startswith("Transport Layer Security")
        )
        host_item = find_item(tls_item, "Host Name: example.com")
        assert host_item is not None, "详情树中未找到 Host Name 字段"
        window.detail_tree.setCurrentItem(host_item)

        start, length = window.hex_view.highlight
        assert length == len("example.com")
        assert window.hex_view.data_length > start
    finally:
        window.close()
