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
    predicate: Callable[[Packet, Decoded], bool]

    def match(self, packet: Packet, decoded: Decoded) -> bool:
        return self.predicate(packet, decoded)


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
