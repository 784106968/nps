"""显示过滤表达式的词法分析。

文法（与 docs/FILTER_SYNTAX.md 保持一致）::

    expr       := or_expr
    or_expr    := and_expr ( "||" and_expr )*
    and_expr   := unary ( "&&" unary )*
    unary      := "!" unary | primary
    primary    := "(" expr ")" | comparison
    comparison := field op value
    op         := "==" | "!=" | "<" | "<=" | ">" | ">="
    value      := integer | "quoted string" | identifier
"""

from __future__ import annotations

from dataclasses import dataclass


class FilterError(ValueError):
    """表达式错误：带字符位置，便于界面定位。"""

    def __init__(self, message: str, position: int, expression: str = "") -> None:
        super().__init__(message)
        self.message = message
        self.position = position
        self.expression = expression

    def __str__(self) -> str:
        return f"第 {self.position + 1} 列：{self.message}"


@dataclass(frozen=True, slots=True)
class Token:
    kind: str
    value: str
    position: int


_SYMBOLS = (
    ("&&", "AND"),
    ("||", "OR"),
    ("==", "OP"),
    ("!=", "OP"),
    ("<=", "OP"),
    (">=", "OP"),
)

_KEYWORDS = {"and": "AND", "or": "OR", "not": "NOT"}

# IPv4 / IPv6 / CIDR 允许的字符；用于把 10.0.0.1、fe80::1、10.0.0.0/8 识别为一个整体
_ADDRESS_CHARS = set("0123456789abcdefABCDEF:./")


def _is_ident_start(char: str) -> bool:
    return char.isalpha() or char == "_"


def _is_ident_char(char: str) -> bool:
    return char.isalnum() or char in "._"


def _read_string(text: str, start: int) -> tuple[str, int]:
    quote = text[start]
    chars: list[str] = []
    index = start + 1
    length = len(text)
    while index < length:
        char = text[index]
        if char == "\\" and index + 1 < length:
            following = text[index + 1]
            chars.append({"n": "\n", "t": "\t", "\\": "\\", quote: quote}.get(following, following))
            index += 2
            continue
        if char == quote:
            return "".join(chars), index + 1
        chars.append(char)
        index += 1
    raise FilterError("字符串缺少结束引号", start, text)


def tokenize(text: str) -> list[Token]:
    tokens: list[Token] = []
    index = 0
    length = len(text)
    while index < length:
        char = text[index]

        if char.isspace():
            index += 1
            continue
        if char == "(":
            tokens.append(Token("LPAREN", char, index))
            index += 1
            continue
        if char == ")":
            tokens.append(Token("RPAREN", char, index))
            index += 1
            continue

        matched = False
        for symbol, kind in _SYMBOLS:
            if text.startswith(symbol, index):
                tokens.append(Token(kind, symbol, index))
                index += len(symbol)
                matched = True
                break
        if matched:
            continue

        if char in "<>":
            tokens.append(Token("OP", char, index))
            index += 1
            continue
        if char == "!":
            tokens.append(Token("NOT", char, index))
            index += 1
            continue
        if char in "\"'":
            start = index
            value, index = _read_string(text, index)
            tokens.append(Token("STRING", value, start))
            continue
        if char.isdigit():
            start = index
            while index < length and text[index] in _ADDRESS_CHARS:
                index += 1
            word = text[start:index]
            kind = "IP" if any(mark in word for mark in ".:/") else "INT"
            tokens.append(Token(kind, word, start))
            continue
        if char == ":":
            # 以 :: 开头的 IPv6 字面量
            start = index
            while index < length and text[index] in _ADDRESS_CHARS:
                index += 1
            tokens.append(Token("IP", text[start:index], start))
            continue
        if _is_ident_start(char):
            start = index
            index += 1
            while index < length and _is_ident_char(text[index]):
                index += 1
            if index < length and text[index] == ":":
                # fe80::1 这类以字母开头的 IPv6 字面量
                while index < length and text[index] in _ADDRESS_CHARS:
                    index += 1
                tokens.append(Token("IP", text[start:index], start))
                continue
            word = text[start:index]
            tokens.append(Token(_KEYWORDS.get(word.lower(), "IDENT"), word, start))
            continue

        raise FilterError(f"无法识别的字符 {char!r}", index, text)

    tokens.append(Token("EOF", "", length))
    return tokens


__all__ = ["FilterError", "Token", "tokenize"]
