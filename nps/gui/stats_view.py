"""统计视图：协议分布、会话 Top N、吞吐时间线。

数据全部来自会话表与包模型（同一数据源），不做二次统计，
因此表内数字与列表、会话面板始终一致。
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFontMetrics, QPainter
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

TOP_N = 10


class ThroughputChart(QWidget):
    """按秒的包数柱状图。"""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._data: list[tuple[int, int]] = []
        self.setMinimumHeight(120)

    def set_data(self, data: list[tuple[int, int]]) -> None:
        self._data = data
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.fillRect(self.rect(), QColor("#ffffff"))
        painter.setPen(QColor("#b0b0b0"))
        painter.drawRect(self.rect().adjusted(0, 0, -1, -1))

        if not self._data:
            painter.setPen(QColor("#9e9e9e"))
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, "（暂无流量）")
            return

        metrics = QFontMetrics(painter.font())
        max_value = max(count for _, count in self._data) or 1
        left, right = 20, self.width() - 20
        baseline = self.height() - 20
        chart_top = 22
        chart_height = max(10, baseline - chart_top)

        painter.setPen(QColor("#616161"))
        painter.drawText(6, 14, f"峰值 {max_value} 包/秒")
        painter.setPen(QColor("#e0e0e0"))
        painter.drawLine(left, baseline, right, baseline)

        slot = max(1.0, (right - left) / max(len(self._data), 1))
        bar_width = min(16.0, max(1.0, slot - 2))
        for index, (_, count) in enumerate(self._data):
            bar_height = chart_height * count / max_value
            x = left + index * slot + (slot - bar_width) / 2
            painter.fillRect(
                QRectF(x, baseline - bar_height, bar_width, bar_height), QColor("#64b5f6")
            )

        if self._data:
            painter.setPen(QColor("#757575"))
            painter.drawText(6, baseline + metrics.ascent() + 2, "每秒包数（最近 60 秒）")


class StatsView(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(4)

        layout.addWidget(QLabel("协议分布"))
        self.protocol_table = self._make_table(("协议", "包数", "字节"))
        layout.addWidget(self.protocol_table, 2)

        layout.addWidget(QLabel(f"会话 Top {TOP_N}（按字节）"))
        self.top_table = self._make_table(("流", "会话", "字节"))
        layout.addWidget(self.top_table, 2)

        layout.addWidget(QLabel("吞吐时间线"))
        self.timeline = ThroughputChart(self)
        layout.addWidget(self.timeline, 3)

    @staticmethod
    def _make_table(headers: tuple[str, ...]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(list(headers))
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        table.setAlternatingRowColors(True)
        header = table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        table.setMinimumHeight(110)
        return table

    def update_from(self, model) -> None:
        sessions = model.session_table.sessions()

        distribution: dict[str, list[int]] = {}
        for session in sessions:
            name = session.app_protocol or session.protocol
            bucket = distribution.setdefault(name, [0, 0])
            bucket[0] += session.packets_total
            bucket[1] += session.bytes_total

        ordered = sorted(distribution.items(), key=lambda item: item[1][1], reverse=True)
        self._fill(self.protocol_table, [[name, f"{v[0]}", f"{v[1]}"] for name, v in ordered])

        top = sorted(sessions, key=lambda session: session.bytes_total, reverse=True)[:TOP_N]
        self._fill(
            self.top_table,
            [[str(s.stream_id), s.label, f"{s.bytes_total}"] for s in top],
        )

        self.timeline.set_data(model.timeline())

    @staticmethod
    def _fill(table: QTableWidget, rows: list[list[str]]) -> None:
        table.setRowCount(len(rows))
        for row, values in enumerate(rows):
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column > 0:
                    align = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
                    item.setTextAlignment(align)
                table.setItem(row, column, item)
