"""包列表模型：列定义、惰性解析与容量淘汰。"""

from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QColor

from nps.core.packet import Packet
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
}

NUMERIC_COLUMNS = {0, 5}
_NO_PARENT = QModelIndex()


class PacketTableModel(QAbstractTableModel):
    """数据包表格。

    解析是惰性的：只有被显示或选中的包才会解析，避免高流量下把所有 CPU
    花在当前不可见的包上。
    """

    def __init__(self, capacity: int = DEFAULT_CAPACITY, parent=None) -> None:
        super().__init__(parent)
        self._store = PacketStore(capacity)
        self._decoded: dict[int, Decoded] = {}

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
            return PROTOCOL_COLORS.get(self._decoded_for(packet).protocol)
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
        overflow = self._store.overflow_for(len(packets))
        if overflow:
            removed = [self._store[i] for i in range(overflow)]
            self.beginRemoveRows(QModelIndex(), 0, overflow - 1)
            self._store.drop_front(overflow)
            for packet in removed:
                self._decoded.pop(packet.index, None)
            self.endRemoveRows()

        first = len(self._store)
        self.beginInsertRows(QModelIndex(), first, first + len(packets) - 1)
        self._store.extend(packets)
        self.endInsertRows()

    def clear(self) -> None:
        self.beginResetModel()
        self._store.clear()
        self._decoded.clear()
        self.endResetModel()

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
            return decoded.protocol
        if column == 5:
            return str(packet.wirelen)
        return decoded.summary
