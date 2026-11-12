"""进程归属的界面呈现：列文本、tooltip 与状态栏。"""

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
from nps.core.session import SessionTable  # noqa: E402
from nps.gui.main_window import MainWindow  # noqa: E402
from nps.gui.session_model import SessionTableModel  # noqa: E402

CLIENT = ("10.0.0.1", 51234)
SERVER = ("93.184.216.34", 80)


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


def tcp_packet() -> Packet:
    tcp = struct.pack("!HHIIBBHHH", CLIENT[1], SERVER[1], 1, 0, 0x50, 0x02, 64240, 0, 0)
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
        socket.inet_aton(CLIENT[0]),
        socket.inet_aton(SERVER[0]),
    )
    frame = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp
    return Packet(
        index=1,
        ts=1_000.0,
        caplen=len(frame),
        wirelen=len(frame),
        linktype=1,
        raw=memoryview(frame),
    )


def build_model() -> tuple[SessionTableModel, object]:
    table = SessionTable()
    session = table.add(tcp_packet())
    assert session is not None
    model = SessionTableModel(table)
    return model, session


def test_process_column_shows_name_and_pid(app) -> None:
    model, session = build_model()
    session.pid = 1234
    session.process_name = "python.exe"
    session.process_confidence = "exact"

    assert model.data(model.index(0, 7), Qt.ItemDataRole.DisplayRole) == "python.exe (1234)"


def test_process_column_falls_back_to_pid(app) -> None:
    model, session = build_model()
    session.pid = 4321
    session.process_name = None
    session.process_confidence = "port"

    assert model.data(model.index(0, 7), Qt.ItemDataRole.DisplayRole) == "4321"


def test_process_column_marks_port_conflict(app) -> None:
    model, session = build_model()
    session.pid = None
    session.process_name = None
    session.process_confidence = "ambiguous"

    assert model.data(model.index(0, 7), Qt.ItemDataRole.DisplayRole) == "端口冲突"


def test_process_tooltip_contains_confidence(app) -> None:
    model, session = build_model()
    session.pid = 1234
    session.process_name = "python.exe"
    session.process_confidence = "port"
    session.process_note = "仅按本地端口匹配"

    tip = model.data(model.index(0, 7), Qt.ItemDataRole.ToolTipRole)
    assert "python.exe" in tip
    assert "PID 1234" in tip
    assert "仅端口推断" in tip
    assert "仅按本地端口匹配" in tip


def test_status_bar_exposes_attribution_state(app) -> None:
    window = MainWindow()
    try:
        assert window.process_label.text().startswith("进程归属:")
    finally:
        window.close()
