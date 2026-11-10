"""界面 + 真实网卡的端到端测试（本地执行，CI 跳过）。

验证：点"开始"后能真正抓包并进入表格；点"停止"后线程退出。
"""

from __future__ import annotations

import os
import socket
import time

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PySide6", reason="未安装 PySide6（pip install -e '.[gui]'）")

from PySide6.QtWidgets import QApplication  # noqa: E402

from nps.capture.interface import list_interfaces  # noqa: E402
from nps.gui.main_window import MainWindow  # noqa: E402

pytestmark = pytest.mark.requires_npcap

LOOPBACK_HINT = "NPF_Loopback"


@pytest.fixture(scope="module")
def app():
    application = QApplication.instance() or QApplication([])
    yield application


def test_capture_fills_table(app) -> None:
    devices = list_interfaces()
    loopback = next((d for d in devices if LOOPBACK_HINT in d.name), None)
    if loopback is None:
        pytest.skip("未安装回环适配器（Npcap 需勾选 loopback 支持）")

    window = MainWindow()
    try:
        index = window.interface_combo.findData(loopback.name)
        assert index >= 0, "回环设备未出现在下拉列表"
        window.interface_combo.setCurrentIndex(index)
        window.filter_edit.setText("udp")
        window.start_capture()
        assert window._backend is not None, "开始后应持有后端"

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            for _ in range(20):
                sock.sendto(b"nps-gui-test", ("127.0.0.1", 9999))
                time.sleep(0.02)

        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and window.packet_model.rowCount() == 0:
            app.processEvents()
            time.sleep(0.02)

        assert window.packet_model.rowCount() > 0
        window.select_row(0)
        assert window.detail_tree.topLevelItemCount() >= 3
        assert window.hex_view.data_length > 0
    finally:
        window.stop_capture()
        window.close()
