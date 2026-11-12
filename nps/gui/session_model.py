"""会话列表模型（右侧停靠面板）。"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from nps.core.session import Session, SessionTable
from nps.gui.packet_model import PROTOCOL_COLORS

COLUMNS = ("流", "协议", "会话", "包 ↑/↓", "字节 ↑/↓", "时长", "状态", "进程")

_NO_PARENT = QModelIndex()


class SessionTableModel(QAbstractTableModel):
    def __init__(self, table: SessionTable, parent=None) -> None:
        super().__init__(parent)
        self._table = table
        self._sessions: list[Session] = []
        self._last_version = -1
        self.refresh()

    def rowCount(self, parent: QModelIndex = _NO_PARENT) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._sessions)

    def columnCount(self, parent: QModelIndex = _NO_PARENT) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        session = self._sessions[index.row()]
        column = index.column()
        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(session, column)
        if role == Qt.ItemDataRole.ForegroundRole and column == 1:
            return PROTOCOL_COLORS.get(session.app_protocol or session.protocol)
        if role == Qt.ItemDataRole.ToolTipRole:
            lines = [session.label]
            if session.app_protocol:
                source = "DPI 识别" if session.confidence == "dpi" else "端口推断"
                lines.append(f"{session.app_protocol}（{source}：{session.classification_note}）")
            if session.process_confidence:
                label = {
                    "exact": "四元组精确匹配",
                    "port": "仅端口推断",
                    "ambiguous": "端口冲突",
                }.get(session.process_confidence, session.process_confidence)
                process = session.process_name or "—"
                lines.append(f"进程: {process}（PID {session.pid}，{label}）")
                if session.process_note:
                    lines.append(session.process_note)
            return "\n".join(lines)
        if role == Qt.ItemDataRole.TextAlignmentRole and column in {0, 3, 4, 5}:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        return None

    def headerData(  # noqa: N802
        self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole
    ):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section]
        return section + 1

    def refresh(self) -> None:
        # 会话表自带 version，命中时直接返回；避免每秒对 2 万会话做一次
        # O(n) 的签名计算（旧实现要遍历求和 + 取最大时间戳）。
        version = self._table.version
        if version == self._last_version:
            return
        self.beginResetModel()
        self._sessions = self._table.sessions()
        self._last_version = version
        self.endResetModel()

    def invalidate(self) -> None:
        """强制下次 refresh 重建（例如清空之后）。"""
        self._last_version = -1

    def session_at(self, row: int) -> Session | None:
        if 0 <= row < len(self._sessions):
            return self._sessions[row]
        return None

    def row_of(self, stream_id: int) -> int:
        for row, session in enumerate(self._sessions):
            if session.stream_id == stream_id:
                return row
        return -1

    @staticmethod
    def _display(session: Session, column: int) -> str:
        if column == 0:
            return str(session.stream_id)
        if column == 1:
            return session.app_protocol or session.protocol
        if column == 2:
            return session.label
        if column == 3:
            return f"{session.packets_up} / {session.packets_down}"
        if column == 4:
            return f"{session.bytes_up} / {session.bytes_down}"
        if column == 5:
            return f"{session.duration:.1f}s"
        if column == 6:
            return {"active": "进行中", "closing": "关闭中", "closed": "已关闭"}.get(
                session.state, session.state
            )
        if session.pid is None:
            return "端口冲突" if session.process_confidence == "ambiguous" else "—"
        if session.process_name:
            return f"{session.process_name} ({session.pid})"
        return str(session.pid)
