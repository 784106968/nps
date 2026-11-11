"""协议详情树（Packet Details）。"""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QFont, QGuiApplication, QKeySequence
from PySide6.QtWidgets import QAbstractItemView, QMenu, QTreeWidget, QTreeWidgetItem

from nps.decode import Field

_ROLE = Qt.ItemDataRole.UserRole

_PLACEHOLDER = "（选择一个数据包以查看协议分层）"


class DetailTree(QTreeWidget):
    """按层展示解析结果；选中任意节点会发出字节区间，供十六进制视图高亮。"""

    fieldSelected = Signal(int, int)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.setHeaderHidden(True)
        self.setColumnCount(1)
        self.setAlternatingRowColors(True)
        self.setUniformRowHeights(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.setExpandsOnDoubleClick(True)
        self.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.customContextMenuRequested.connect(self._show_menu)
        self.currentItemChanged.connect(self._on_current_changed)
        self.show_placeholder()

    def show_placeholder(self) -> None:
        self.clear()
        item = QTreeWidgetItem([_PLACEHOLDER])
        item.setFlags(Qt.ItemFlag.NoItemFlags)
        self.addTopLevelItem(item)

    def show_layers(self, layers: list[Field]) -> None:
        self.clear()
        if not layers:
            self.show_placeholder()
            return
        for layer in layers:
            item = QTreeWidgetItem([self._layer_text(layer)])
            item.setData(0, _ROLE, (layer.offset, layer.length, layer.name, layer.value))
            font = item.font(0)
            font.setBold(True)
            item.setFont(0, font)
            self.addTopLevelItem(item)
            self._add_children(item, layer.children)
            item.setExpanded(True)

    def clear_data(self) -> None:
        self.show_placeholder()

    # ---- 内部 ----
    def _add_children(self, parent: QTreeWidgetItem, children: list[Field]) -> None:
        for child in children:
            item = QTreeWidgetItem([self._field_text(child)])
            item.setData(0, _ROLE, (child.offset, child.length, child.name, child.value))
            parent.addChild(item)
            if child.children:
                self._add_children(item, child.children)
                item.setExpanded(True)

    @staticmethod
    def _layer_text(layer: Field) -> str:
        return f"{layer.name}, {layer.value}" if layer.value else layer.name

    @staticmethod
    def _field_text(field: Field) -> str:
        return f"{field.name}: {field.value}" if field.value else field.name

    def _on_current_changed(self, current: QTreeWidgetItem | None, previous) -> None:
        if current is None:
            return
        data = current.data(0, _ROLE)
        if not data:
            return
        offset, length = data[0], data[1]
        self.fieldSelected.emit(int(offset), int(length))

    # ---- 复制字段 ----
    def _copy(self, text: str) -> None:
        if text:
            QGuiApplication.clipboard().setText(text)

    def copy_current(self, with_name: bool = False) -> None:
        item = self.currentItem()
        if item is None:
            return
        data = item.data(0, _ROLE)
        if not data:
            return
        name, value = data[2], data[3]
        self._copy(f"{name}: {value}" if with_name else str(value))

    def _show_menu(self, position) -> None:
        item = self.itemAt(position)
        if item is None or not item.data(0, _ROLE):
            return
        self.setCurrentItem(item)
        menu = QMenu(self)
        copy_value = menu.addAction("复制值")
        copy_field = menu.addAction("复制字段（名称: 值）")
        chosen = menu.exec(self.viewport().mapToGlobal(position))
        if chosen is copy_value:
            self.copy_current()
        elif chosen is copy_field:
            self.copy_current(with_name=True)

    def keyPressEvent(self, event) -> None:  # noqa: N802
        if event.matches(QKeySequence.StandardKey.Copy):
            self.copy_current()
            event.accept()
            return
        super().keyPressEvent(event)


def default_font() -> QFont:  # pragma: no cover - 供主题定制预留
    return QFont()
