"""会话列表模型（右侧停靠面板）。"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor

from nps.core.session import Session, SessionTable

COLUMNS = ("流", "协议", "会话", "包 ↑/↓", "字节 ↑/↓", "时长", "状态", "进程")

PROTOCOL_COLORS = {
    "TCP": QColor("#1a237e"),
    "UDP": QColor("#0b6b3a"),
    "ICMP": QColor("#6a1b9a"),
    "ICMPv6": QColor("#6a1b9a"),
}

_NO_PARENT = QModelIndex()


class SessionTableModel(QAbstractTableModel):
    def __init__(self, table: SessionTable, parent=None) -> None:
        super().__init__(parent)
        self._table = table
        self._sessions: list[Session] = []
        self._signature: tuple[int, int, float] = (-1, 0, 0.0)
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
            return PROTOCOL_COLORS.get(session.protocol)
        if role == Qt.ItemDataRole.ToolTipRole:
            return session.label
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
        sessions = self._table.sessions()
        signature = (
            len(sessions),
            sum(session.packets_total for session in sessions),
            max((session.last_ts for session in sessions), default=0.0),
        )
        if signature == self._signature:
            return
        self.beginResetModel()
        self._sessions = sessions
        self._signature = signature
        self.endResetModel()

    def invalidate(self) -> None:
        """强制下次 refresh 重建（例如清空之后）。"""
        self._signature = (-1, 0, 0.0)

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
            return session.protocol
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
        return "—" if session.pid is None else str(session.pid)
