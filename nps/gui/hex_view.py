"""十六进制视图（Packet in Binary）。

自绘而非用 QPlainTextEdit，是为了支持按字节区间高亮：
点击详情树中的字段时，对应字节在这里被标出。
"""

from __future__ import annotations

from PySide6.QtCore import QRectF, Qt
from PySide6.QtGui import QColor, QFontDatabase, QFontMetrics, QPainter
from PySide6.QtWidgets import QAbstractScrollArea

BYTES_PER_LINE = 16
HIGHLIGHT = QColor("#ffe082")
OFFSET_COLOR = QColor("#8a8a8a")
ASCII_COLOR = QColor("#455a64")
EMPTY_TEXT = "（无数据，请在上方选择一个数据包）"


class HexView(QAbstractScrollArea):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._data = b""
        self._highlight_start = 0
        self._highlight_len = 0

        font = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont)
        font.setPointSize(10)
        self.setFont(font)
        self._font = font
        metrics = QFontMetrics(font)
        self._char_w = max(1, metrics.horizontalAdvance("0"))
        self._line_h = max(12, metrics.height() + 4)

        self.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAsNeeded)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.viewport().setAutoFillBackground(True)

    # ---- 数据 ----
    @property
    def data_length(self) -> int:
        return len(self._data)

    @property
    def highlight(self) -> tuple[int, int]:
        return self._highlight_start, self._highlight_len

    def set_data(self, data: bytes) -> None:
        self._data = bytes(data)
        self.clear_highlight()
        self.verticalScrollBar().setValue(0)
        self._update_scrollbars()
        self.viewport().update()

    def clear(self) -> None:
        self.set_data(b"")

    def highlight_range(self, offset: int, length: int) -> None:
        if length <= 0 or not self._data:
            self.clear_highlight()
            return
        start = max(0, min(offset, len(self._data) - 1))
        end = max(start + 1, min(offset + length, len(self._data)))
        self._highlight_start = start
        self._highlight_len = end - start
        self._scroll_to(start)
        self.viewport().update()

    def clear_highlight(self) -> None:
        self._highlight_start = 0
        self._highlight_len = 0
        self.viewport().update()

    # ---- 滚动 ----
    def _rows(self) -> int:
        return (len(self._data) + BYTES_PER_LINE - 1) // BYTES_PER_LINE

    def _visible_rows(self) -> int:
        return max(1, self.viewport().height() // self._line_h)

    def _update_scrollbars(self) -> None:
        bar = self.verticalScrollBar()
        rows = self._rows()
        bar.setRange(0, max(0, rows - self._visible_rows()))
        bar.setPageStep(self._visible_rows())
        bar.setSingleStep(1)

    def _scroll_to(self, offset: int) -> None:
        row = offset // BYTES_PER_LINE
        bar = self.verticalScrollBar()
        if row < bar.value() or row >= bar.value() + self._visible_rows():
            bar.setValue(max(0, row - self._visible_rows() // 2))

    def resizeEvent(self, event) -> None:  # noqa: N802
        super().resizeEvent(event)
        self._update_scrollbars()

    def wheelEvent(self, event) -> None:  # noqa: N802
        delta = event.angleDelta().y()
        bar = self.verticalScrollBar()
        bar.setValue(bar.value() - (3 if delta > 0 else -3))
        event.accept()

    # ---- 绘制 ----
    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self.viewport())
        painter.fillRect(self.viewport().rect(), QColor("#ffffff"))
        painter.setFont(self._font)

        if not self._data:
            painter.setPen(OFFSET_COLOR)
            painter.drawText(12, self._line_h, EMPTY_TEXT)
            return

        painter.setPen(QColor("#000000"))
        x_offset = 8
        x_hex = x_offset + 9 * self._char_w
        x_ascii = x_hex + BYTES_PER_LINE * 3 * self._char_w + 2 * self._char_w
        first_row = self.verticalScrollBar().value()
        rows_on_screen = self._visible_rows() + 1
        highlight_end = self._highlight_start + self._highlight_len

        for line in range(rows_on_screen):
            row = first_row + line
            start = row * BYTES_PER_LINE
            if start >= len(self._data):
                break
            base_y = line * self._line_h
            text_y = base_y + self._line_h - 6

            painter.setPen(OFFSET_COLOR)
            painter.drawText(x_offset, text_y, f"{start:08x}")

            for col in range(BYTES_PER_LINE):
                position = start + col
                if position >= len(self._data):
                    break
                x = x_hex + col * 3 * self._char_w
                if self._highlight_len and self._highlight_start <= position < highlight_end:
                    painter.fillRect(
                        QRectF(x - 1, base_y + 1, 2 * self._char_w + 1, self._line_h - 2),
                        HIGHLIGHT,
                    )
                painter.setPen(QColor("#000000"))
                painter.drawText(x, text_y, f"{self._data[position]:02x}")

                char = self._data[position]
                printable = chr(char) if 32 <= char < 127 else "."
                ax = x_ascii + col * self._char_w
                if self._highlight_len and self._highlight_start <= position < highlight_end:
                    painter.fillRect(
                        QRectF(ax - 1, base_y + 1, self._char_w + 1, self._line_h - 2),
                        HIGHLIGHT,
                    )
                painter.setPen(ASCII_COLOR)
                painter.drawText(ax, text_y, printable)
