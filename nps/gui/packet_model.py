"""包列表模型：列定义、惰性解析与容量淘汰。"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor

from nps.core.packet import Packet
from nps.core.session import SessionTable
from nps.core.store import DEFAULT_CAPACITY, PacketStore
from nps.decode import Decoded, decode_packet

COLUMNS = ("No.", "Time", "Source", "Destination", "Protocol", "Length", "Info")

PROTOCOL_COLORS = {
    "TCP": QColor("#1a237e"),
    "UDP": QColor("#0b6b3a"),
    "ICMP": QColor("#6a1b9a"),
    "ICMPv6": QColor("#6a1b9a"),
    "ARP": QColor("#8d6e00"),
    "IPv6": QColor("#004d40"),
    "HTTP": QColor("#0d47a1"),
    "TLS": QColor("#4a148c"),
    "SSH": QColor("#00695c"),
    "DNS": QColor("#ef6c00"),
    "BitTorrent": QColor("#c62828"),
}

TIMELINE_SECONDS = 60

NUMERIC_COLUMNS = {0, 5}
HIGHLIGHT_COLOR = QColor("#e3f2fd")
_NO_PARENT = QModelIndex()


class PacketTableModel(QAbstractTableModel):
    """数据包表格。

    解析是惰性的：只有被显示或选中的包才会解析，避免高流量下把所有 CPU
    花在当前不可见的包上。
    """

    def __init__(self, capacity: int = DEFAULT_CAPACITY, parent=None, resolver=None) -> None:
        super().__init__(parent)
        self._store = PacketStore(capacity)
        self._decoded: dict[int, Decoded] = {}
        self.session_table = SessionTable(resolver=resolver)
        self._highlight_stream: int | None = None
        self._timeline: dict[int, int] = {}
        # stream_id → 行号，供流时序图按流取包；容量淘汰时整体失效重建
        self._stream_rows: dict[int, list[int]] = {}

    # ---- Qt 接口 ----
    def rowCount(self, parent: QModelIndex = _NO_PARENT) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(self._store)

    def columnCount(self, parent: QModelIndex = _NO_PARENT) -> int:  # noqa: N802
        return 0 if parent.isValid() else len(COLUMNS)

    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None
        row, column = index.row(), index.column()
        packet = self._store[row]

        if role == Qt.ItemDataRole.DisplayRole:
            return self._display(packet, column)
        if role == Qt.ItemDataRole.TextAlignmentRole and column in NUMERIC_COLUMNS:
            return int(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        if role == Qt.ItemDataRole.ForegroundRole and column == 4:
            return PROTOCOL_COLORS.get(self.protocol_label(row))
        if role == Qt.ItemDataRole.ToolTipRole and column == 6:
            return self._decoded_for(packet).summary
        if role == Qt.ItemDataRole.ToolTipRole and column == 4:
            session = self.session_for(packet)
            if session is not None and session.app_protocol:
                source = "DPI 识别" if session.confidence == "dpi" else "端口推断"
                return f"{session.app_protocol}（{source}：{session.classification_note}）"
            return self._decoded_for(packet).protocol
        if (
            role == Qt.ItemDataRole.BackgroundRole
            and self._highlight_stream is not None
            and packet.stream_id == self._highlight_stream
        ):
            return HIGHLIGHT_COLOR
        return None

    def headerData(  # noqa: N802
        self,
        section: int,
        orientation: Qt.Orientation,
        role: int = Qt.ItemDataRole.DisplayRole,
    ):
        if role != Qt.ItemDataRole.DisplayRole:
            return None
        if orientation == Qt.Orientation.Horizontal:
            return COLUMNS[section]
        return section + 1

    # ---- 业务接口 ----
    def append_batch(self, packets: list[Packet]) -> None:
        if not packets:
            return
        for packet in packets:
            self.session_table.add(packet)
            second = int(packet.ts)
            self._timeline[second] = self._timeline.get(second, 0) + 1

        overflow = self._store.overflow_for(len(packets))
        if overflow:
            removed = [self._store[i] for i in range(overflow)]
            self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
            self._store.drop_front(overflow)
            for packet in removed:
                self._decoded.pop(packet.index, None)
            self.endRemoveRows()
            # 行号整体前移，旧索引全部失效
            self._stream_rows.clear()

        first = len(self._store)
        self.beginInsertRows(QModelIndex(), first, first + len(packets) - 1)
        self._store.extend(packets)
        for offset, packet in enumerate(packets):
            if packet.stream_id is not None:
                self._stream_rows.setdefault(packet.stream_id, []).append(first + offset)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._store.clear()
        self._decoded.clear()
        self.session_table.clear()
        self._highlight_stream = None
        self._timeline.clear()
        self._stream_rows.clear()
        self.endResetModel()

    def set_highlight_stream(self, stream_id: int | None) -> None:
        if stream_id == self._highlight_stream:
            return
        self._highlight_stream = stream_id
        if self.rowCount():
            self.dataChanged.emit(
                self.index(0, 0),
                self.index(self.rowCount() - 1, 0),
                [Qt.ItemDataRole.BackgroundRole],
            )

    def row_of_stream(self, stream_id: int) -> int:
        """返回该会话第一条包所在行，找不到返回 -1。"""
        for row in range(len(self._store)):
            packet = self._store[row]
            if packet.stream_id == stream_id:
                return row
        return -1

    def packet_at(self, row: int) -> Packet | None:
        if 0 <= row < len(self._store):
            return self._store[row]
        return None

    def decoded_at(self, row: int) -> Decoded | None:
        packet = self.packet_at(row)
        return None if packet is None else self._decoded_for(packet)

    def packets(self) -> list[Packet]:
        """快照当前表内的全部包（导出用）。"""
        return [self._store[i] for i in range(len(self._store))]

    def packets_of_stream(self, stream_id: int) -> list[Packet]:
        """按流取当前表内的包，供流时序图使用。

        维护 ``stream_id → 行号`` 索引后是 O(k)（k 为该流包数）；
        索引缺失时回退到一次线性扫描，保证功能不受影响。
        """
        rows = self._stream_rows.get(stream_id)
        if rows is None:
            return [
                self._store[i]
                for i in range(len(self._store))
                if self._store[i].stream_id == stream_id
            ]
        total = len(self._store)
        return [self._store[row] for row in rows if 0 <= row < total]

    def session_for(self, packet: Packet):
        if packet.stream_id is None:
            return None
        return self.session_table.get(packet.stream_id)

    def protocol_label(self, row: int) -> str:
        """优先显示 DPI/端口推断出的应用层协议。"""
        packet = self.packet_at(row)
        if packet is None:
            return ""
        session = self.session_for(packet)
        if session is not None and session.app_protocol:
            return session.app_protocol
        return self._decoded_for(packet).protocol

    def timeline(self, seconds: int = TIMELINE_SECONDS) -> list[tuple[int, int]]:
        """按秒聚合的包数，供吞吐时间线使用。"""
        items = sorted(self._timeline.items())[-seconds:]
        return items

    def last_timestamp(self) -> float:
        """最后一个包的抓包时间，用作会话老化基准。"""
        if not len(self._store):
            return 0.0
        return self._store[len(self._store) - 1].ts

    @property
    def dropped_old(self) -> int:
        return self._store.dropped_old

    @property
    def capacity(self) -> int:
        return self._store.capacity

    # ---- 内部 ----
    def _decoded_for(self, packet: Packet) -> Decoded:
        cached = self._decoded.get(packet.index)
        if cached is None:
            cached = decode_packet(packet)
            self._decoded[packet.index] = cached
        return cached

    def _display(self, packet: Packet, column: int) -> str:
        if column == 0:
            return str(packet.index)
        if column == 1:
            return packet.ts_text
        decoded = self._decoded_for(packet)
        if column == 2:
            return decoded.src
        if column == 3:
            return decoded.dst
        if column == 4:
            session = self.session_for(packet)
            if session is not None and session.app_protocol:
                return session.app_protocol
            return decoded.protocol
        if column == 5:
            return str(packet.wirelen)
        return decoded.summary
