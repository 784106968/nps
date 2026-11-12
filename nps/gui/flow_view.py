"""流时序图：横轴时间、纵轴两端，观察单个会话的往返节奏。

设计取舍：
- 10,000 包在 1,000 px 宽度下平均每包 0.1 px，逐包绘制既慢又不可读，
  因此密集时按**像素列聚合**：同一列只画一条线，颜色表示主导方向；
- 稀疏时逐包绘制，标注包长与 TCP 标志（SYN/FIN/RST/PSH）；
- 缩放只改变视窗，不重排数据；拖动按像素换算时间；
- 包本身来自 ``PacketTableModel.packets_of_stream``，与列表、会话共用同一份
  ``Packet`` 对象，不复制 ``raw``。
"""

from __future__ import annotations

from bisect import bisect_left, bisect_right
from collections.abc import Iterable
from dataclasses import dataclass

from PySide6.QtCore import QPointF, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFontMetrics, QPainter, QPainterPath, QPen, QPolygonF
from PySide6.QtWidgets import QSizePolicy, QToolTip, QWidget

from nps.core.packet import Packet
from nps.core.session import Session, parse_flow

MARGIN_LEFT = 136.0
MARGIN_RIGHT = 16.0
MARGIN_TOP = 32.0
MARGIN_BOTTOM = 28.0
MIN_SPAN = 1e-4
DEFAULT_PAD = 1.0
SPARSE_SLOT = 28.0
FLAG_SLOT = 46.0

COLOR_BG = QColor("#ffffff")
COLOR_BORDER = QColor("#e0e0e0")
COLOR_AXIS = QColor("#bdbdbd")
COLOR_TEXT = QColor("#424242")
COLOR_MUTED = QColor("#9e9e9e")
COLOR_UP = QColor("#1565c0")
COLOR_DOWN = QColor("#2e7d32")
COLOR_FLAG = QColor("#c62828")

_FLAG_LABELS = ((0x02, "SYN"), (0x01, "FIN"), (0x04, "RST"), (0x08, "PSH"))


@dataclass(frozen=True, slots=True)
class FlowPoint:
    ts: float
    up: bool
    length: int
    index: int
    flags: str = ""


def _flag_text(flags: int) -> str:
    if not flags:
        return ""
    names = [name for bit, name in _FLAG_LABELS if flags & bit]
    return "·".join(names[:2])


def _endpoint_text(endpoint: tuple[str, int]) -> str:
    ip, port = endpoint
    return ip if not port else f"{ip}:{port}"


def _format_offset(seconds: float) -> str:
    if abs(seconds) >= 60:
        minutes, rest = divmod(seconds, 60)
        return f"{int(minutes):+d}m{abs(rest):04.1f}s"
    if abs(seconds) >= 10:
        return f"{seconds:+.2f}s"
    return f"{seconds:+.3f}s"


def collect_points(session: Session, packets: Iterable[Packet]) -> list[FlowPoint]:
    """把包列表转成按时间排序的时序点，方向以会话发起方为基准。"""
    initiator = session.initiator
    points: list[FlowPoint] = []
    for packet in packets:
        flow = parse_flow(packet)
        if flow is None:
            continue
        up = (flow.src, flow.sport) == initiator
        points.append(
            FlowPoint(
                ts=packet.ts,
                up=up,
                length=packet.wirelen,
                index=packet.index,
                flags=_flag_text(flow.tcp_flags),
            )
        )
    points.sort(key=lambda point: point.ts)
    return points


class FlowView(QWidget):
    """单个会话的时序图，带滚轮缩放与拖动平移。"""

    pointClicked = Signal(int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._session: Session | None = None
        self._points: list[FlowPoint] = []
        self._start = 0.0
        self._end = 1.0
        self._view_start = 0.0
        self._view_end = 1.0
        self._drag_x: float | None = None
        self._drag_start = 0.0
        self._drag_end = 0.0
        self._tip_key: tuple[int, int] | None = None
        self.setMinimumHeight(180)
        self.setMouseTracking(True)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)

    # ---- 数据接口 ----
    @property
    def session(self) -> Session | None:
        return self._session

    def points(self) -> tuple[FlowPoint, ...]:
        return tuple(self._points)

    def point_count(self) -> int:
        return len(self._points)

    def view_range(self) -> tuple[float, float]:
        return self._view_start, self._view_end

    def set_flow(
        self,
        session: Session | None,
        packets: Iterable[Packet] = (),
        keep_view: bool = False,
    ) -> None:
        """更新数据；``keep_view=True`` 用于抓包中追加，避免重置用户缩放。"""
        same_session = (
            keep_view
            and session is not None
            and self._session is not None
            and session.stream_id == self._session.stream_id
        )
        old_view = (self._view_start, self._view_end)
        self._session = session
        self._points = collect_points(session, packets) if session is not None else []
        if self._points:
            self._start = self._points[0].ts
            self._end = self._points[-1].ts
        else:
            self._start, self._end = 0.0, 1.0
        self._tip_key = None
        if same_session:
            self._view_start, self._view_end = old_view
            self._clamp_view()
            self.update()
        else:
            self.reset_view()

    def clear(self) -> None:
        self._session = None
        self._points = []
        self._start, self._end = 0.0, 1.0
        self._view_start, self._view_end = 0.0, 1.0
        self._tip_key = None
        QToolTip.hideText()
        self.update()

    def reset_view(self) -> None:
        span = self._end - self._start
        if span <= MIN_SPAN:
            center = (self._start + self._end) / 2
            self._view_start = center - DEFAULT_PAD / 2
            self._view_end = center + DEFAULT_PAD / 2
        else:
            pad = span * 0.02
            self._view_start = self._start - pad
            self._view_end = self._end + pad
        self.update()

    def zoom(self, factor: float, anchor: float = 0.5) -> None:
        """按比例缩放时间窗，``anchor`` 是 0–1 的鼠标横向位置。"""
        if not self._points:
            return
        span = self._view_end - self._view_start
        data_span = max(self._end - self._start, MIN_SPAN)
        new_span = min(max(span * factor, data_span / 200.0), data_span * 4.0)
        anchor = min(max(anchor, 0.0), 1.0)
        anchor_ts = self._view_start + span * anchor
        self._view_start = anchor_ts - new_span * anchor
        self._view_end = self._view_start + new_span
        self._clamp_view()
        self.update()

    # ---- 绘制 ----
    def sizeHint(self) -> QSize:  # noqa: N802
        return QSize(680, 320)

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.fillRect(self.rect(), COLOR_BG)
        painter.setPen(QPen(COLOR_BORDER, 1))
        painter.drawRect(self.rect().adjusted(0, 0, -1, -1))

        rect = self._plot_rect()
        if rect.width() < 60 or rect.height() < 40:
            return
        if self._session is None:
            self._draw_placeholder(painter, "（选中一个包或会话，查看该流的时序）")
            return

        self._draw_header(painter, rect)
        self._draw_endpoints(painter, rect)
        self._draw_time_axis(painter, rect)

        visible = self._visible_points()
        if not visible:
            self._draw_placeholder(painter, "（当前时间窗内没有包，滚轮缩放或双击复位）")
            return
        slot = rect.width() / len(visible)
        if slot >= SPARSE_SLOT:
            self._draw_sparse(painter, rect, visible)
        else:
            self._draw_dense(painter, rect, visible)

    def _plot_rect(self) -> QRectF:
        width = max(0.0, self.width() - MARGIN_LEFT - MARGIN_RIGHT)
        height = max(0.0, self.height() - MARGIN_TOP - MARGIN_BOTTOM)
        return QRectF(MARGIN_LEFT, MARGIN_TOP, width, height)

    @staticmethod
    def _endpoint_y(rect: QRectF) -> tuple[float, float]:
        return rect.top() + 8.0, rect.bottom() - 8.0

    def _x_for(self, ts: float, rect: QRectF) -> float:
        span = max(self._view_end - self._view_start, MIN_SPAN)
        return rect.left() + (ts - self._view_start) / span * rect.width()

    def _visible_points(self) -> list[FlowPoint]:
        left = bisect_left(self._points, self._view_start, key=lambda point: point.ts)
        right = bisect_right(self._points, self._view_end, key=lambda point: point.ts)
        return self._points[left:right]

    def _draw_placeholder(self, painter: QPainter, text: str) -> None:
        painter.setPen(COLOR_MUTED)
        painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, text)

    def _draw_header(self, painter: QPainter, rect: QRectF) -> None:
        session = self._session
        if session is None:
            return
        protocol = session.app_protocol or session.protocol
        title = f"流 #{session.stream_id} · {protocol} · {len(self._points)} 包"
        metrics = QFontMetrics(painter.font())
        painter.setPen(COLOR_TEXT)
        painter.drawText(
            QRectF(rect.left(), 5, max(60.0, rect.width() - 170), 18),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            metrics.elidedText(title, Qt.TextElideMode.ElideRight, int(rect.width() - 170)),
        )
        painter.setPen(COLOR_MUTED)
        painter.drawText(
            QRectF(rect.right() - 168, 5, 168, 18),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            "滚轮缩放 · 拖动平移 · 双击复位",
        )

    def _draw_endpoints(self, painter: QPainter, rect: QRectF) -> None:
        session = self._session
        if session is None:
            return
        y_top, y_bottom = self._endpoint_y(rect)
        metrics = QFontMetrics(painter.font())
        limit = int(MARGIN_LEFT - 16)
        labels = (
            (y_top, f"客户端 {_endpoint_text(session.client)}"),
            (y_bottom, f"服务端 {_endpoint_text(session.server)}"),
        )
        painter.setPen(COLOR_TEXT)
        for y, text in labels:
            painter.drawText(
                QRectF(4, y - 9, MARGIN_LEFT - 16, 18),
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                metrics.elidedText(text, Qt.TextElideMode.ElideMiddle, limit),
            )
        painter.setPen(QPen(COLOR_AXIS, 1, Qt.PenStyle.DashLine))
        painter.drawLine(QPointF(rect.left(), y_top), QPointF(rect.right(), y_top))
        painter.drawLine(QPointF(rect.left(), y_bottom), QPointF(rect.right(), y_bottom))

    def _draw_time_axis(self, painter: QPainter, rect: QRectF) -> None:
        y_top, y_bottom = self._endpoint_y(rect)
        mid = (y_top + y_bottom) / 2
        painter.setPen(QPen(COLOR_AXIS, 1, Qt.PenStyle.DotLine))
        painter.drawLine(QPointF(rect.left(), mid), QPointF(rect.right(), mid))

        span = self._view_end - self._view_start
        for index in range(5):
            ratio = index / 4
            x = rect.left() + rect.width() * ratio
            painter.setPen(COLOR_AXIS)
            painter.drawLine(QPointF(x, y_bottom + 2), QPointF(x, y_bottom + 7))
            painter.setPen(COLOR_MUTED)
            painter.drawText(
                QRectF(x - 45, y_bottom + 8, 90, 16),
                Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                _format_offset(self._view_start + span * ratio - self._start),
            )

    def _draw_sparse(self, painter: QPainter, rect: QRectF, points: list[FlowPoint]) -> None:
        y_top, y_bottom = self._endpoint_y(rect)
        slot = rect.width() / max(len(points), 1)
        show_flags = slot >= FLAG_SLOT
        mid = (y_top + y_bottom) / 2
        for point in points:
            x = self._x_for(point.ts, rect)
            color = COLOR_UP if point.up else COLOR_DOWN
            painter.setPen(QPen(color, 1.2))
            painter.drawLine(QPointF(x, y_top), QPointF(x, y_bottom))
            self._draw_arrow(painter, x, y_bottom if point.up else y_top, point.up, color)

            painter.setPen(COLOR_TEXT)
            if point.up:
                text_rect = QRectF(x + 4, mid - 8, 34, 16)
                align = Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter
            else:
                text_rect = QRectF(x - 38, mid - 8, 34, 16)
                align = Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            painter.drawText(text_rect, align, str(point.length))

            if show_flags and point.flags:
                painter.setPen(COLOR_FLAG)
                painter.drawText(
                    QRectF(x - 30, mid + 7, 60, 14),
                    Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop,
                    point.flags,
                )

    def _draw_dense(self, painter: QPainter, rect: QRectF, points: list[FlowPoint]) -> None:
        y_top, y_bottom = self._endpoint_y(rect)
        mid = (y_top + y_bottom) / 2
        columns: dict[int, int] = {}
        for point in points:
            column = int(round(self._x_for(point.ts, rect) - rect.left()))
            columns[column] = columns.get(column, 0) | (1 if point.up else 2)

        up_path = QPainterPath()
        down_path = QPainterPath()
        for column, flags in columns.items():
            x = rect.left() + column
            if flags == 1:
                up_path.moveTo(x, y_top)
                up_path.lineTo(x, y_bottom)
            elif flags == 2:
                down_path.moveTo(x, y_top)
                down_path.lineTo(x, y_bottom)
            else:
                up_path.moveTo(x, y_top)
                up_path.lineTo(x, mid)
                down_path.moveTo(x, mid)
                down_path.lineTo(x, y_bottom)

        painter.setPen(QPen(COLOR_UP, 1))
        painter.drawPath(up_path)
        painter.setPen(QPen(COLOR_DOWN, 1))
        painter.drawPath(down_path)

        painter.setPen(COLOR_MUTED)
        painter.drawText(
            QRectF(rect.left(), rect.top() + 2, 230, 16),
            Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
            f"按像素聚合为 {len(columns)} 列",
        )
        painter.setPen(COLOR_UP)
        painter.drawText(
            QRectF(rect.right() - 148, rect.top() + 2, 66, 16),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            "■ 上行",
        )
        painter.setPen(COLOR_DOWN)
        painter.drawText(
            QRectF(rect.right() - 74, rect.top() + 2, 74, 16),
            Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
            "■ 下行",
        )

    @staticmethod
    def _draw_arrow(painter: QPainter, x: float, y: float, up: bool, color: QColor) -> None:
        offset = 5.0 if up else -5.0
        arrow = QPolygonF(
            [
                QPointF(x, y),
                QPointF(x - 3.5, y - offset),
                QPointF(x + 3.5, y - offset),
            ]
        )
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(color)
        painter.drawPolygon(arrow)
        painter.setBrush(Qt.BrushStyle.NoBrush)

    # ---- 交互 ----
    def wheelEvent(self, event) -> None:  # noqa: N802
        if not self._points:
            return
        delta = event.angleDelta().y()
        if not delta:
            return
        rect = self._plot_rect()
        if rect.width() <= 0:
            return
        ratio = (event.position().x() - rect.left()) / rect.width()
        self.zoom(0.8 if delta > 0 else 1.25, ratio)
        event.accept()

    def mousePressEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton and self._points:
            self._drag_x = event.position().x()
            self._drag_start = self._view_start
            self._drag_end = self._view_end
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
            event.accept()

    def mouseMoveEvent(self, event) -> None:  # noqa: N802
        if self._drag_x is not None:
            rect = self._plot_rect()
            if rect.width() > 0:
                shift = (
                    (self._drag_x - event.position().x())
                    / rect.width()
                    * (self._drag_end - self._drag_start)
                )
                self._view_start = self._drag_start + shift
                self._view_end = self._drag_end + shift
                self._clamp_view()
                self._tip_key = None
                self.update()
            event.accept()
            return
        self._show_tooltip(event)

    def mouseReleaseEvent(self, event) -> None:  # noqa: N802
        if event.button() == Qt.MouseButton.LeftButton and self._drag_x is not None:
            self._drag_x = None
            self.unsetCursor()
            event.accept()

    def mouseDoubleClickEvent(self, event) -> None:  # noqa: N802
        self.reset_view()
        event.accept()

    def leaveEvent(self, event) -> None:  # noqa: N802
        self._tip_key = None
        QToolTip.hideText()

    def keyPressEvent(self, event) -> None:  # noqa: N802
        key = event.key()
        if key in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
            self.zoom(0.8)
        elif key == Qt.Key.Key_Minus:
            self.zoom(1.25)
        elif key == Qt.Key.Key_0:
            self.reset_view()
        else:
            super().keyPressEvent(event)

    def _clamp_view(self) -> None:
        span = self._view_end - self._view_start
        if span <= 0:
            return
        lower = self._start - span
        if self._view_start < lower:
            self._view_end += lower - self._view_start
            self._view_start = lower
        elif self._view_start > self._end:
            self._view_end -= self._view_start - self._end
            self._view_start = self._end

    def _show_tooltip(self, event) -> None:
        if not self._points:
            return
        rect = self._plot_rect()
        position = event.position()
        if rect.width() <= 0 or not rect.contains(position):
            return
        span = max(self._view_end - self._view_start, MIN_SPAN)
        ts = self._view_start + (position.x() - rect.left()) / rect.width() * span
        index = bisect_left(self._points, ts, key=lambda point: point.ts)
        candidates: list[FlowPoint] = []
        if index > 0:
            candidates.append(self._points[index - 1])
        if index < len(self._points):
            candidates.append(self._points[index])
        if not candidates:
            return
        point = min(candidates, key=lambda item: abs(item.ts - ts))
        key = (point.index, index)
        if key == self._tip_key:
            return
        self._tip_key = key
        direction = "上行 →" if point.up else "← 下行"
        flags = f" {point.flags}" if point.flags else ""
        text = f"#{point.index} {direction} {point.length} B{flags}\n+{point.ts - self._start:.6f}s"
        QToolTip.showText(event.globalPosition().toPoint(), text, self)
