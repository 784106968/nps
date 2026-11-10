"""显示过滤表达式的语法分析（递归下降）。

优先级由低到高：``||`` < ``&&`` < ``!`` < 比较。
"""

from __future__ import annotations

from dataclasses import dataclass

from nps.filters.lexer import FilterError, Token, tokenize


@dataclass(frozen=True, slots=True)
class Literal:
    value: str
    is_number: bool
    position: int


class Node:
    """表达式节点基类。"""


@dataclass(frozen=True, slots=True)
class Compare(Node):
    field: str
    operator: str
    literal: Literal
    position: int


@dataclass(frozen=True, slots=True)
class And(Node):
    left: Node
    right: Node


@dataclass(frozen=True, slots=True)
class Or(Node):
    left: Node
    right: Node


@dataclass(frozen=True, slots=True)
class Not(Node):
    operand: Node


class Parser:
    def __init__(self, tokens: list[Token], expression: str) -> None:
        self._tokens = tokens
        self._expression = expression
        self._index = 0

    def parse(self) -> Node:
        if self._peek().kind == "EOF":
            raise FilterError("表达式为空", 0, self._expression)
        node = self._parse_or()
        token = self._peek()
        if token.kind != "EOF":
            raise FilterError(f"多余的内容 {token.value!r}", token.position, self._expression)
        return node

    # ---- 各级文法 ----
    def _parse_or(self) -> Node:
        node = self._parse_and()
        while self._peek().kind == "OR":
            self._advance()
            node = Or(node, self._parse_and())
        return node

    def _parse_and(self) -> Node:
        node = self._parse_not()
        while self._peek().kind == "AND":
            self._advance()
            node = And(node, self._parse_not())
        return node

    def _parse_not(self) -> Node:
        if self._peek().kind == "NOT":
            self._advance()
            return Not(self._parse_not())
        return self._parse_primary()

    def _parse_primary(self) -> Node:
        token = self._peek()
        if token.kind == "LPAREN":
            self._advance()
            node = self._parse_or()
            closing = self._peek()
            if closing.kind != "RPAREN":
                raise FilterError("缺少右括号", closing.position, self._expression)
            self._advance()
            return node
        return self._parse_comparison()

    def _parse_comparison(self) -> Node:
        field = self._expect("IDENT", "需要字段名")
        operator = self._expect("OP", "需要比较运算符（==、!=、<、<=、>、>=）")
        literal = self._parse_literal()
        return Compare(field.value, operator.value, literal, field.position)

    def _parse_literal(self) -> Literal:
        token = self._peek()
        if token.kind == "INT":
            self._advance()
            return Literal(token.value, True, token.position)
        if token.kind in {"STRING", "IP"}:
            self._advance()
            return Literal(token.value, False, token.position)
        if token.kind == "IDENT":
            self._advance()
            return Literal(token.value, False, token.position)
        raise FilterError("比较运算符后面需要值", token.position, self._expression)

    # ---- 辅助 ----
    def _peek(self) -> Token:
        return self._tokens[self._index]

    def _advance(self) -> Token:
        token = self._tokens[self._index]
        self._index += 1
        return token

    def _expect(self, kind: str, message: str) -> Token:
        token = self._peek()
        if token.kind != kind:
            raise FilterError(message, token.position, self._expression)
        return self._advance()


def parse(expression: str) -> Node:
    return Parser(tokenize(expression), expression).parse()


__all__ = ["And", "Compare", "Literal", "Node", "Not", "Or", "Parser", "parse"]
