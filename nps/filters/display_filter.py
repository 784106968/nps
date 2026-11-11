"""显示过滤器对外接口：把表达式编译成可复用的谓词。"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from nps.core.packet import Packet
from nps.decode import Decoded
from nps.filters.evaluator import FIELD_NAMES, FIELD_SPECS, build_predicate
from nps.filters.lexer import FilterError, tokenize
from nps.filters.parser import Parser


@dataclass(frozen=True, slots=True)
class DisplayFilter:
    expression: str
    predicate: Callable[..., bool]

    def match(self, packet: Packet, decoded: Decoded, session: object | None = None) -> bool:
        """``session`` 可选：传入时会话上的 DPI 标签优先于传输层协议。"""
        return self.predicate(packet, decoded, session)


def compile_filter(expression: str) -> DisplayFilter:
    text = expression.strip()
    if not text:
        raise FilterError("表达式为空", 0, expression)
    node = Parser(tokenize(text), text).parse()
    return DisplayFilter(text, build_predicate(node, text))


__all__ = [
    "FIELD_NAMES",
    "FIELD_SPECS",
    "DisplayFilter",
    "compile_filter",
]
