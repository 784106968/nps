"""字段表与求值。

求值发生在用户态，只影响"显示什么"，不重新抓包。
字段缺失（例如非 TCP 包查询 ``tcp.port``）一律视为不匹配，而不是报错——
这与 Wireshark 的行为一致，也避免用户在混合流量下频繁出现错误提示。
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from nps.core.packet import Packet
from nps.decode import Decoded
from nps.filters.lexer import FilterError
from nps.filters.parser import And, Compare, Node, Not, Or

Getter = Callable[[Packet, Decoded], object | None]

IP_PROTOCOL_NAMES = {
    "icmp": 1,
    "igmp": 2,
    "tcp": 6,
    "udp": 17,
    "ipv6": 41,
    "gre": 47,
    "esp": 50,
    "ah": 51,
    "icmpv6": 58,
}


@dataclass(frozen=True, slots=True)
class FieldSpec:
    kind: str  # "int" | "ip" | "text"
    description: str
    getter: Getter


def _pair(first: object | None, second: object | None) -> frozenset[object] | None:
    values = {value for value in (first, second) if value is not None}
    return frozenset(values) if values else None


def _fields(packet: Packet, decoded: Decoded) -> dict[str, Any]:
    return decoded.fields


FIELD_SPECS: dict[str, FieldSpec] = {
    "ip.src": FieldSpec("ip", "源 IP 地址", lambda p, d: _fields(p, d).get("ip.src")),
    "ip.dst": FieldSpec("ip", "目的 IP 地址", lambda p, d: _fields(p, d).get("ip.dst")),
    "ip.addr": FieldSpec(
        "ip",
        "源或目的 IP 地址",
        lambda p, d: _pair(_fields(p, d).get("ip.src"), _fields(p, d).get("ip.dst")),
    ),
    "ip.proto": FieldSpec(
        "int",
        "IP 协议号，可写 tcp / udp / icmp / icmpv6",
        lambda p, d: _fields(p, d).get("ip.proto"),
    ),
    "ip.version": FieldSpec(
        "int", "IP 版本（4 或 6）", lambda p, d: _fields(p, d).get("ip.version")
    ),
    "ip.len": FieldSpec(
        "int", "IPv4 总长度 / IPv6 载荷长度", lambda p, d: _fields(p, d).get("ip.len")
    ),
    "ip.ttl": FieldSpec(
        "int", "IPv4 TTL / IPv6 Hop Limit", lambda p, d: _fields(p, d).get("ip.ttl")
    ),
    "tcp.port": FieldSpec(
        "int",
        "TCP 源或目的端口",
        lambda p, d: _pair(_fields(p, d).get("tcp.srcport"), _fields(p, d).get("tcp.dstport")),
    ),
    "tcp.srcport": FieldSpec("int", "TCP 源端口", lambda p, d: _fields(p, d).get("tcp.srcport")),
    "tcp.dstport": FieldSpec("int", "TCP 目的端口", lambda p, d: _fields(p, d).get("tcp.dstport")),
    "tcp.flags.syn": FieldSpec(
        "int", "SYN 标志（0/1）", lambda p, d: _fields(p, d).get("tcp.flags.syn")
    ),
    "tcp.flags.ack": FieldSpec(
        "int", "ACK 标志（0/1）", lambda p, d: _fields(p, d).get("tcp.flags.ack")
    ),
    "tcp.len": FieldSpec("int", "TCP 载荷字节数", lambda p, d: _fields(p, d).get("tcp.len")),
    "udp.port": FieldSpec(
        "int",
        "UDP 源或目的端口",
        lambda p, d: _pair(_fields(p, d).get("udp.srcport"), _fields(p, d).get("udp.dstport")),
    ),
    "udp.srcport": FieldSpec("int", "UDP 源端口", lambda p, d: _fields(p, d).get("udp.srcport")),
    "udp.dstport": FieldSpec("int", "UDP 目的端口", lambda p, d: _fields(p, d).get("udp.dstport")),
    "udp.len": FieldSpec("int", "UDP 长度字段", lambda p, d: _fields(p, d).get("udp.len")),
    "icmp.type": FieldSpec("int", "ICMP 类型", lambda p, d: _fields(p, d).get("icmp.type")),
    "icmp.code": FieldSpec("int", "ICMP 代码", lambda p, d: _fields(p, d).get("icmp.code")),
    "arp.op": FieldSpec(
        "int", "ARP 操作码（1 请求 / 2 应答）", lambda p, d: _fields(p, d).get("arp.op")
    ),
    "protocol": FieldSpec(
        "text", "协议名，大小写不敏感（TCP / UDP / ICMP / ARP…）", lambda p, d: d.protocol
    ),
    "stream_id": FieldSpec("int", "会话编号（P3 起有值）", lambda p, d: p.stream_id),
    "frame.len": FieldSpec("int", "线路长度（字节）", lambda p, d: p.wirelen),
    "frame.number": FieldSpec("int", "帧序号", lambda p, d: p.index),
}

FIELD_NAMES = tuple(FIELD_SPECS)


# ---- 编译期类型检查 ----
def build_predicate(node: Node, expression: str) -> Callable[..., bool]:
    if isinstance(node, And):
        left = build_predicate(node.left, expression)
        right = build_predicate(node.right, expression)
        return lambda packet, decoded, session=None: (
            left(packet, decoded, session) and right(packet, decoded, session)
        )
    if isinstance(node, Or):
        left = build_predicate(node.left, expression)
        right = build_predicate(node.right, expression)
        return lambda packet, decoded, session=None: (
            left(packet, decoded, session) or right(packet, decoded, session)
        )
    if isinstance(node, Not):
        operand = build_predicate(node.operand, expression)
        return lambda packet, decoded, session=None: not operand(packet, decoded, session)
    if isinstance(node, Compare):
        return _build_compare(node, expression)
    raise FilterError("无法识别的表达式", 0, expression)  # pragma: no cover


def _build_compare(node: Compare, expression: str) -> Callable[..., bool]:
    spec = FIELD_SPECS.get(node.field)
    if spec is None:
        raise FilterError(f"未知字段 {node.field!r}", node.position, expression)

    literal = node.literal
    operator = node.operator
    expected: object

    if spec.kind == "int":
        if operator not in {"==", "!=", "<", "<=", ">", ">="}:
            raise FilterError(
                f"字段 {node.field} 不支持运算符 {operator}", literal.position, expression
            )
        if literal.is_number:
            expected = int(literal.value)
        elif literal.value.lower() in IP_PROTOCOL_NAMES and node.field == "ip.proto":
            expected = IP_PROTOCOL_NAMES[literal.value.lower()]
        else:
            raise FilterError(
                f"字段 {node.field} 需要整数，得到 {literal.value!r}", literal.position, expression
            )
    elif spec.kind == "ip":
        if operator not in {"==", "!="}:
            raise FilterError(
                f"IP 字段只支持 == 与 !=，不支持 {operator}", literal.position, expression
            )
        if literal.is_number:
            raise FilterError(
                f"字段 {node.field} 需要 IP 地址，得到数字 {literal.value}",
                literal.position,
                expression,
            )
        try:
            expected = ipaddress.ip_network(literal.value, strict=False)
        except ValueError as exc:
            raise FilterError(
                f"无法解析 IP 地址/网段 {literal.value!r}", literal.position, expression
            ) from exc
    else:  # text
        if operator not in {"==", "!="}:
            raise FilterError("文本字段只支持 == 与 !=", literal.position, expression)
        if literal.is_number:
            raise FilterError(
                f"字段 {node.field} 需要字符串，得到数字 {literal.value}",
                literal.position,
                expression,
            )
        expected = literal.value.lower()

    kind = spec.kind
    getter = spec.getter
    op = operator
    is_protocol = node.field == "protocol"

    def predicate(packet: Packet, decoded: Decoded, session: object | None = None) -> bool:
        if is_protocol:
            # protocol 优先取会话上的 DPI 标签，其次是解码得到的传输层协议
            app = getattr(session, "app_protocol", None)
            actual = app or decoded.protocol
        else:
            actual = getter(packet, decoded)
        if actual is None:
            return False
        values = actual if isinstance(actual, frozenset) else (actual,)
        if not values:
            return False
        results = [_match_one(kind, value, op, expected) for value in values]
        if op == "==":
            return any(results)
        if op == "!=":
            return all(results)
        return any(results)

    return predicate


def _match_one(kind: str, value: object, operator: str, expected: object) -> bool:
    if kind == "ip":
        try:
            address = ipaddress.ip_address(str(value))
        except ValueError:
            return False
        network = expected
        assert isinstance(network, ipaddress.IPv4Network | ipaddress.IPv6Network)
        return address in network if operator == "==" else address not in network

    if kind == "text":
        left = str(value).lower()
        right = str(expected)
        return left == right if operator == "==" else left != right

    try:
        left_int = int(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return False
    right_int = int(expected)  # type: ignore[arg-type]
    if operator == "==":
        return left_int == right_int
    if operator == "!=":
        return left_int != right_int
    if operator == "<":
        return left_int < right_int
    if operator == "<=":
        return left_int <= right_int
    if operator == ">":
        return left_int > right_int
    return left_int >= right_int


__all__ = [
    "FIELD_NAMES",
    "FIELD_SPECS",
    "FieldSpec",
    "build_predicate",
]
