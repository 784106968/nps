"""流时序图：方向、缩放、渲染性能与主窗口联动。"""

from __future__ import annotations

import os
import socket
import struct
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="未安装 PySide6（pip install -e '.[gui]'）")

from PySide6.QtGui import QPixmap  # noqa: E402

from nps.core.packet import Packet  # noqa: E402
from nps.core.session import Session, SessionTable  # noqa: E402
from nps.gui.flow_view import FlowView  # noqa: E402
from nps.gui.main_window import MainWindow  # noqa: E402

CLIENT = ("10.0.0.1", 51234)
SERVER = ("93.184.216.34", 80)


@pytest.fixture(scope="module")
def app():
    from PySide6.QtWidgets import QApplication

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


def build_session(count: int) -> tuple[Session, list[Packet]]:
    table = SessionTable()
    packets: list[Packet] = []
    for index in range(count):
        if index % 2 == 0:
            frame = tcp_frame(CLIENT, SERVER, 0x18, b"x" * 10)
        else:
            frame = tcp_frame(SERVER, CLIENT, 0x18, b"y" * 5)
        item = packet(frame, index + 1, 1_000.0 + index * 0.001)
        table.add(item)
        packets.append(item)
    session = table.get(1)
    assert session is not None
    return session, packets


def test_points_mark_direction_and_length(app) -> None:
    session, packets = build_session(6)
    view = FlowView()
    view.set_flow(session, packets)

    points = view.points()
    assert len(points) == 6
    assert [point.up for point in points] == [True, False, True, False, True, False]
    assert points[0].length == len(packets[0].raw)
    assert points[0].flags == "PSH"


def test_zoom_shrinks_window_and_reset_restores(app) -> None:
    session, packets = build_session(10)
    view = FlowView()
    view.set_flow(session, packets)
    before = view.view_range()

    view.zoom(0.5, 0.5)
    after = view.view_range()
    assert (after[1] - after[0]) < (before[1] - before[0])

    view.reset_view()
    assert view.view_range() == pytest.approx(before)


def test_keep_view_preserves_zoom_when_appending(app) -> None:
    session, packets = build_session(20)
    view = FlowView()
    view.set_flow(session, packets)
    view.zoom(0.5, 0.5)
    before = view.view_range()

    view.set_flow(session, [*packets, *packets], keep_view=True)
    assert view.view_range() == pytest.approx(before)


def test_ten_thousand_packets_render_under_one_second(app) -> None:
    session, packets = build_session(10_000)
    view = FlowView()
    view.resize(1200, 500)
    view.set_flow(session, packets)
    assert view.point_count() == 10_000

    pixmap = QPixmap(1200, 500)
    started = time.perf_counter()
    view.render(pixmap)
    elapsed = time.perf_counter() - started
    assert elapsed < 1.0, f"10k 包渲染耗时 {elapsed * 1000:.0f} ms"


def test_main_window_shows_flow_for_selected_packet(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(handshake())
        window.select_row(3)

        assert window.flow_view.point_count() == 6
        assert window.flow_view.session is not None
        assert window.flow_dock.widget() is window.flow_view
    finally:
        window.close()


def test_session_click_updates_flow(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(handshake())
        window._on_session_clicked(window.session_model.index(0, 0))
        assert window.flow_view.point_count() == 6
    finally:
        window.close()


def test_clear_resets_flow(app) -> None:
    window = MainWindow()
    try:
        window.feed_packets(handshake())
        window.select_row(0)
        window.clear_packets()
        assert window.flow_view.point_count() == 0
        assert window.flow_view.session is None
    finally:
        window.close()


def test_empty_render_does_not_raise(app) -> None:
    view = FlowView()
    view.resize(400, 200)
    view.set_flow(None, [])
    pixmap = QPixmap(400, 200)
    view.render(pixmap)
    assert view.point_count() == 0
