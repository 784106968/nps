"""主窗口：Wireshark 风格三窗格布局。

    ┌──────────────────────────────┐
    │ Packet List   （包列表）      │
    ├──────────────────────────────┤
    │ Packet Details（协议分层）    │
    ├──────────────────────────────┤
    │ Packet in Binary（十六进制）  │
    └──────────────────────────────┘

三个面板由 QSplitter 垂直排列，可拖动分隔条调整高度；
选中包 → 详情树与十六进制同步刷新；选中字段 → 十六进制高亮对应字节。
"""

from __future__ import annotations

import time

from PySide6.QtCore import QItemSelectionModel, Qt, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDockWidget,
    QFileDialog,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QToolBar,
    QVBoxLayout,
    QWidget,
)

from nps.capture.backend import CaptureConfig
from nps.capture.interface import choose_default, list_interfaces
from nps.capture.libpcap import PcapError
from nps.capture.pcap_backend import PcapBackend
from nps.core.buffer import BoundedPacketQueue
from nps.core.packet import Packet
from nps.filters import FilterError
from nps.gui.detail_tree import DetailTree
from nps.gui.filter_proxy import PacketFilterProxy
from nps.gui.hex_view import HexView
from nps.gui.packet_model import COLUMNS, PacketTableModel
from nps.gui.session_model import SessionTableModel
from nps.pcapio import write_pcap

TICK_MS = 16
DRAIN_PER_TICK = 300
DRAIN_CATCH_UP = 5_000
QUEUE_CAPACITY = 100_000
MODEL_CAPACITY = 200_000
COLUMN_WIDTHS = (72, 120, 170, 170, 90, 70)

STYLE_SHEET = """
QMainWindow { background: #f5f5f5; }
QTableView, QTreeWidget {
    background: #ffffff;
    selection-background-color: #cfe8ff;
    selection-color: #000000;
    border: none;
}
QHeaderView::section {
    background: #ececec;
    padding: 4px 6px;
    border: 0px;
    border-right: 1px solid #d8d8d8;
    border-bottom: 1px solid #d0d0d0;
}
QLabel#paneTitle {
    background: #e8e8e8;
    color: #333333;
    padding: 4px 8px;
    border-bottom: 1px solid #d0d0d0;
}
QComboBox, QLineEdit { padding: 3px 6px; }
"""


class MainWindow(QMainWindow):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setWindowTitle("NPS — Network Packet Sniffer")
        self.resize(1200, 820)
        self.setStyleSheet(STYLE_SHEET)

        self._queue = BoundedPacketQueue(QUEUE_CAPACITY)
        self._backend: PcapBackend | None = None
        self._paused = False

        self.packet_model = PacketTableModel(MODEL_CAPACITY, self)
        self.filter_proxy = PacketFilterProxy(self)
        self.session_model = SessionTableModel(self.packet_model.session_table, self)
        self.table = QTableView()
        self.detail_tree = DetailTree()
        self.hex_view = HexView()
        self.splitter = QSplitter(Qt.Orientation.Vertical)

        self._build_toolbar()
        self._build_panes()
        self._build_session_dock()
        self._build_statusbar()

        self._timer = QTimer(self)
        self._timer.setInterval(TICK_MS)
        self._timer.timeout.connect(self._on_tick)

        self._session_timer = QTimer(self)
        self._session_timer.setInterval(1_000)
        self._session_timer.timeout.connect(self._on_session_tick)
        self._session_timer.start()

        self.detail_tree.fieldSelected.connect(self.hex_view.highlight_range)
        self.refresh_interfaces()
        self._set_running(False)
        self._update_status("就绪")

    # ---- 构建界面 ----
    def _build_toolbar(self) -> None:
        toolbar = QToolBar("主工具栏", self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        toolbar.addWidget(QLabel(" 接口 "))
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(340)
        toolbar.addWidget(self.interface_combo)

        self.refresh_button = QPushButton("刷新")
        self.refresh_button.clicked.connect(self.refresh_interfaces)
        toolbar.addWidget(self.refresh_button)

        toolbar.addSeparator()
        toolbar.addWidget(QLabel(" 捕获过滤器 "))
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("BPF，例如 tcp port 80 或 icmp")
        self.filter_edit.setMinimumWidth(280)
        self.filter_edit.setClearButtonEnabled(True)
        toolbar.addWidget(self.filter_edit)

        self.start_button = QPushButton("开始")
        self.start_button.clicked.connect(self.start_capture)
        toolbar.addWidget(self.start_button)

        self.stop_button = QPushButton("停止")
        self.stop_button.clicked.connect(self.stop_capture)
        toolbar.addWidget(self.stop_button)

        self.pause_button = QPushButton("暂停")
        self.pause_button.clicked.connect(self.toggle_pause)
        toolbar.addWidget(self.pause_button)

        self.clear_button = QPushButton("清空")
        self.clear_button.clicked.connect(self.clear_packets)
        toolbar.addWidget(self.clear_button)

        self.save_button = QPushButton("保存")
        self.save_button.setToolTip("把当前列表导出为 PCAP 文件")
        self.save_button.clicked.connect(self.save_pcap)
        toolbar.addWidget(self.save_button)

        toolbar.addSeparator()
        self.autoscroll = QCheckBox("自动滚动")
        self.autoscroll.setChecked(True)
        toolbar.addWidget(self.autoscroll)

        # ---- 第二行：显示过滤器 ----
        self.addToolBarBreak()
        display_bar = QToolBar("显示过滤器", self)
        display_bar.setMovable(False)
        self.addToolBar(display_bar)

        display_bar.addWidget(QLabel(" 显示过滤器 "))
        self.display_filter_edit = QLineEdit()
        self.display_filter_edit.setPlaceholderText(
            "例如 ip.src == 10.0.0.1 && tcp.port == 443，留空表示不过滤"
        )
        self.display_filter_edit.setMinimumWidth(420)
        self.display_filter_edit.setClearButtonEnabled(True)
        display_bar.addWidget(self.display_filter_edit)

        self.filter_error_label = QLabel("")
        self.filter_error_label.setStyleSheet("color: #c62828; padding-left: 8px;")
        display_bar.addWidget(self.filter_error_label)

        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(250)
        self._filter_timer.timeout.connect(self._apply_display_filter)
        self.display_filter_edit.textChanged.connect(lambda _: self._filter_timer.start())
        self.display_filter_edit.returnPressed.connect(self._apply_display_filter)

    def _build_panes(self) -> None:
        self._configure_table()

        self.splitter.addWidget(self._wrap_pane("Packet List", self.table))
        self.splitter.addWidget(self._wrap_pane("Packet Details", self.detail_tree))
        self.splitter.addWidget(self._wrap_pane("Packet in Binary", self.hex_view))
        self.splitter.setChildrenCollapsible(False)
        self.splitter.setHandleWidth(8)
        self.splitter.setStretchFactor(0, 3)
        self.splitter.setStretchFactor(1, 2)
        self.splitter.setStretchFactor(2, 2)
        self.splitter.setSizes([420, 320, 260])
        self.setCentralWidget(self.splitter)

    def _configure_table(self) -> None:
        self.filter_proxy.setSourceModel(self.packet_model)
        self.table.setModel(self.filter_proxy)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.setWordWrap(False)
        self.table.setShowGrid(False)
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(22)
        header = self.table.horizontalHeader()
        # 先设模式再设列宽：setSectionResizeMode 会重置列宽，顺序反过来会把宽度冲掉
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column, width in enumerate(COLUMN_WIDTHS):
            self.table.setColumnWidth(column, width)
        header.setSectionResizeMode(len(COLUMNS) - 1, QHeaderView.ResizeMode.Stretch)
        self.table.selectionModel().currentRowChanged.connect(self._on_current_row_changed)

    def _wrap_pane(self, title: str, widget: QWidget) -> QWidget:
        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)
        label = QLabel(title)
        label.setObjectName("paneTitle")
        layout.addWidget(label)
        layout.addWidget(widget, 1)
        return container

    def _build_session_dock(self) -> None:
        self.session_view = QTableView()
        self.session_view.setModel(self.session_model)
        self.session_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.session_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.session_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.session_view.setAlternatingRowColors(True)
        self.session_view.verticalHeader().setVisible(False)
        self.session_view.verticalHeader().setDefaultSectionSize(22)
        header = self.session_view.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for column, width in enumerate((40, 54, 244, 62, 84, 52, 58)):
            self.session_view.setColumnWidth(column, width)
        header.setSectionResizeMode(7, QHeaderView.ResizeMode.Stretch)
        self.session_view.clicked.connect(self._on_session_clicked)
        self.session_view.doubleClicked.connect(self._on_session_activated)

        dock = QDockWidget("会话", self)
        dock.setObjectName("sessionDock")
        dock.setAllowedAreas(
            Qt.DockWidgetArea.RightDockWidgetArea | Qt.DockWidgetArea.BottomDockWidgetArea
        )
        dock.setWidget(self.session_view)
        dock.setMinimumWidth(620)
        self.addDockWidget(Qt.DockWidgetArea.RightDockWidgetArea, dock)
        self.resizeDocks([dock], [700], Qt.Orientation.Horizontal)
        self.session_dock = dock

    def _build_statusbar(self) -> None:
        bar = self.statusBar()
        self.status_label = QLabel("就绪")
        self.stream_label = QLabel("流: 0")
        self.count_label = QLabel("包数: 0")
        self.drop_label = QLabel("队列 0 / 丢弃 0 / 内核 0")
        bar.addWidget(self.status_label, 1)
        bar.addPermanentWidget(self.stream_label)
        bar.addPermanentWidget(self.count_label)
        bar.addPermanentWidget(self.drop_label)

    # ---- 设备与采集 ----
    def refresh_interfaces(self) -> None:
        self.interface_combo.clear()
        try:
            devices = list_interfaces()
        except PcapError as exc:
            self.interface_combo.addItem("（libpcap 不可用）", None)
            self._update_status(f"设备枚举失败：{exc}")
            return
        if not devices:
            self.interface_combo.addItem("（无可用网卡）", None)
            self._update_status("未枚举到网卡，请确认 Npcap / libpcap 已安装")
            return

        for device in devices:
            self.interface_combo.addItem(device.label, device.name)
        try:
            default = choose_default(devices)
        except PcapError:
            default = devices[0]
        index = self.interface_combo.findData(default.name)
        if index >= 0:
            self.interface_combo.setCurrentIndex(index)

    def start_capture(self) -> None:
        if self._backend is not None:
            return
        device = self.interface_combo.currentData()
        if not device:
            QMessageBox.warning(
                self, "无法开始", "没有可用网卡，请先检查 Npcap / libpcap 安装与权限。"
            )
            return

        backend = PcapBackend()
        try:
            backend.open(CaptureConfig(device=str(device)))
            expression = self.filter_edit.text().strip()
            if expression:
                backend.set_filter(expression)
            backend.start(self._queue.put)
        except PcapError as exc:
            backend.close()
            QMessageBox.critical(self, "抓包失败", str(exc))
            self._update_status(f"抓包失败：{exc}")
            return

        self._backend = backend
        self._paused = False
        self.pause_button.setText("暂停")
        self._timer.start()
        self._set_running(True)
        self._update_status("捕获中")

    def stop_capture(self) -> None:
        self._timer.stop()
        backend, self._backend = self._backend, None
        if backend is not None:
            backend.close()
        remaining = self._queue.drain(DRAIN_CATCH_UP)
        if remaining:
            self.packet_model.append_batch(remaining)
            if self.autoscroll.isChecked():
                self.table.scrollToBottom()
        self._set_running(False)
        self._update_status("已停止")

    def toggle_pause(self) -> None:
        if self._backend is None:
            return
        self._paused = not self._paused
        self.pause_button.setText("继续" if self._paused else "暂停")
        self._update_status(
            f"已暂停刷新（仍在捕获，队列积压 {self._queue.qsize()}）" if self._paused else "捕获中"
        )

    def clear_packets(self) -> None:
        self.packet_model.clear()
        self.detail_tree.clear_data()
        self.hex_view.clear()
        self.session_model.invalidate()
        self.session_model.refresh()
        self._update_status()

    def save_pcap(self) -> None:
        packets = self.packet_model.packets()
        if not packets:
            QMessageBox.information(self, "没有数据", "当前列表为空，没有可导出的数据包。")
            return
        confirm = QMessageBox.question(
            self,
            "导出前确认",
            "捕获内容可能包含账号、Cookie 等敏感信息。\n"
            "请确认已获得授权，并在分享前做脱敏处理。\n\n是否继续导出？",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if confirm != QMessageBox.StandardButton.Yes:
            return

        path, _ = QFileDialog.getSaveFileName(self, "另存为 PCAP", "capture.pcap", "PCAP (*.pcap)")
        if not path:
            return
        try:
            count = write_pcap(path, packets)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "导出失败", str(exc))
            return
        self._update_status(f"已导出 {count} 个包到 {path}")

    # ---- 刷新 ----
    def _on_tick(self) -> None:
        if self._paused:
            self._update_status()
            return
        limit = DRAIN_CATCH_UP if self._queue.qsize() > 2_000 else DRAIN_PER_TICK
        batch = self._queue.drain(limit)
        if batch:
            self.packet_model.append_batch(batch)
            if self.autoscroll.isChecked():
                self.table.scrollToBottom()
        self._update_status()

    def _on_current_row_changed(self, current, previous) -> None:
        if not current.isValid():
            return
        source_index = self.filter_proxy.mapToSource(current)
        if not source_index.isValid():
            return
        row = source_index.row()
        packet = self.packet_model.packet_at(row)
        decoded = self.packet_model.decoded_at(row)
        if packet is None or decoded is None:
            return
        self.detail_tree.blockSignals(True)
        self.detail_tree.show_layers(decoded.layers)
        self.detail_tree.blockSignals(False)
        self.hex_view.set_data(bytes(packet.raw))
        self.packet_model.set_highlight_stream(packet.stream_id)
        self._sync_session_selection(packet.stream_id)

    def _on_session_tick(self) -> None:
        # 用"最后一个包的时间戳"做老化基准：离线回放旧 PCAP 时不会因为系统时间而误清空
        now = self.packet_model.last_timestamp() or time.time()
        removed = self.packet_model.session_table.expire(now)
        self.session_model.refresh()
        if removed:
            self._update_status()

    def _on_session_clicked(self, index) -> None:
        session = self.session_model.session_at(index.row())
        if session is None:
            return
        self.packet_model.set_highlight_stream(session.stream_id)

    def _on_session_activated(self, index) -> None:
        session = self.session_model.session_at(index.row())
        if session is None:
            return
        self.packet_model.set_highlight_stream(session.stream_id)
        row = self.packet_model.row_of_stream(session.stream_id)
        if row < 0:
            self.status_label.setText("该流的包已被容量上限淘汰")
            return
        if self.select_row(row):
            self.table.scrollTo(self.table.currentIndex())
        else:
            self.status_label.setText(f"流 #{session.stream_id} 的包被显示过滤隐藏")

    def _sync_session_selection(self, stream_id: int | None) -> None:
        if stream_id is None:
            return
        row = self.session_model.row_of(stream_id)
        if row < 0:
            return
        index = self.session_model.index(row, 0)
        if index == self.session_view.currentIndex():
            return
        self.session_view.blockSignals(True)
        self.session_view.setCurrentIndex(index)
        self.session_view.scrollTo(index)
        self.session_view.blockSignals(False)

    def _apply_display_filter(self) -> bool:
        expression = self.display_filter_edit.text()
        try:
            self.filter_proxy.apply(expression)
        except FilterError as exc:
            # 保留上一条有效规则，只提示错误，避免列表在输入过程中反复跳动
            self.display_filter_edit.setStyleSheet("border: 1px solid #c62828;")
            self.filter_error_label.setText(f"× {exc}")
            self._update_status(f"过滤表达式无效：{exc}")
            return False

        self.display_filter_edit.setStyleSheet("")
        self.filter_error_label.setText("")
        if not self.table.currentIndex().isValid():
            self.detail_tree.clear_data()
            self.hex_view.clear()
        self._update_status()
        return True

    def _set_running(self, running: bool) -> None:
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        self.pause_button.setEnabled(running)
        self.interface_combo.setEnabled(not running)
        self.refresh_button.setEnabled(not running)
        self.filter_edit.setEnabled(not running)

    def _update_status(self, text: str | None = None) -> None:
        if text is not None:
            self.status_label.setText(text)
        elif self._backend is not None and not self._paused:
            self.status_label.setText("捕获中")

        self.stream_label.setText(f"流: {len(self.packet_model.session_table)}")
        total = self.packet_model.rowCount()
        visible = self.filter_proxy.rowCount()
        if self.filter_proxy.active:
            self.count_label.setText(f"包数: {total} / 显示 {visible}")
        else:
            self.count_label.setText(f"包数: {total}")
        kernel_drop = 0
        if self._backend is not None:
            try:
                stats = self._backend.stats()
                kernel_drop = stats.drop + stats.ifdrop
            except PcapError:
                kernel_drop = 0
        self.drop_label.setText(
            f"队列 {self._queue.qsize()} / 丢弃 {self._queue.dropped} / 内核 {kernel_drop}"
        )

    # ---- 测试辅助 ----
    def feed_packets(self, packets: list[Packet]) -> None:
        self.packet_model.append_batch(packets)
        if packets:
            self.table.scrollToBottom()
        self.session_model.refresh()
        self._update_status()

    def select_row(self, row: int) -> bool:
        """按源模型行号选中；返回是否可见（被过滤掉时返回 False）。"""
        source_index = self.packet_model.index(row, 0)
        proxy_index = self.filter_proxy.mapFromSource(source_index)
        if not proxy_index.isValid():
            return False
        self.table.selectionModel().setCurrentIndex(
            proxy_index,
            QItemSelectionModel.SelectionFlag.ClearAndSelect
            | QItemSelectionModel.SelectionFlag.Rows,
        )
        return True

    def set_display_filter(self, expression: str) -> bool:
        """设置显示过滤器；返回是否编译成功（失败时保留上一条有效规则）。"""
        self.display_filter_edit.setText(expression)
        self._filter_timer.stop()
        return self._apply_display_filter()

    def closeEvent(self, event) -> None:  # noqa: N802
        self.stop_capture()
        super().closeEvent(event)
