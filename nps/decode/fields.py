"""解析结果的数据结构。"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(slots=True)
class Field:
    """一个协议层或层内字段。

    ``offset/length`` 指向帧内字节区间，选中时用来高亮十六进制视图。
    """

    name: str
    value: str = ""
    offset: int = 0
    length: int = 0
    children: list[Field] = field(default_factory=list)

    def add(self, name: str, value: object = "", offset: int = 0, length: int = 0) -> Field:
        node = Field(name=name, value=str(value), offset=offset, length=length)
        self.children.append(node)
        return node

    @property
    def is_layer(self) -> bool:
        return bool(self.children)

    def __str__(self) -> str:  # pragma: no cover - 调试用
        return f"{self.name}: {self.value}" if self.value else self.name


@dataclass(slots=True)
class Decoded:
    """一个数据包的解析结果。

    ``fields`` 是给显示过滤器用的扁平字段表（如 ``ip.src``、``tcp.dstport``），
    与详情树解耦：界面看树，过滤看键值。
    """

    layers: list[Field] = field(default_factory=list)
    protocol: str = "UNKNOWN"
    src: str = "-"
    dst: str = "-"
    summary: str = ""
    fields: dict[str, object] = field(default_factory=dict)

    @property
    def names(self) -> list[str]:
        return [layer.name for layer in self.layers]

    def put(self, **values: object) -> None:
        self.fields.update(values)
