"""显示过滤的代理模型。

用 QSortFilterProxyModel 而不是删包：被过滤掉的包仍在模型里，
清空表达式即可恢复，帧序号（No.）也不会重新编号。
"""

from __future__ import annotations

from PySide6.QtCore import QModelIndex, QSortFilterProxyModel

from nps.filters import DisplayFilter, compile_filter


class PacketFilterProxy(QSortFilterProxyModel):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._display_filter: DisplayFilter | None = None
        self.setDynamicSortFilter(True)

    @property
    def expression(self) -> str:
        return self._display_filter.expression if self._display_filter else ""

    @property
    def active(self) -> bool:
        return self._display_filter is not None

    def apply(self, expression: str) -> None:
        """编译并应用；表达式非法时抛出 FilterError，调用方负责提示。"""
        text = expression.strip()
        self._display_filter = compile_filter(text) if text else None
        # Qt 6.12 起 invalidateFilter / invalidateRowsFilter 均已弃用，用公共 invalidate()
        self.invalidate()

    def filterAcceptsRow(  # noqa: N802
        self, source_row: int, source_parent: QModelIndex
    ) -> bool:
        if self._display_filter is None:
            return True
        model = self.sourceModel()
        packet = model.packet_at(source_row)
        decoded = model.decoded_at(source_row)
        if packet is None or decoded is None:
            return False
        session = (
            model.session_table.get(packet.stream_id) if packet.stream_id is not None else None
        )
        return self._display_filter.match(packet, decoded, session)
