"""显示过滤：词法、语法、求值与错误提示。"""

from __future__ import annotations

import socket
import struct

import pytest

from nps.core.packet import Packet
from nps.decode import decode_packet
from nps.filters import FilterError, compile_filter
from nps.filters.lexer import tokenize
from nps.filters.parser import And, Compare, Not, Or, parse

MAC_A = bytes.fromhex("020000000001")
MAC_B = bytes.fromhex("020000000002")


# ---- 报文构造 ----
def ethernet(payload: bytes, ethertype: int = 0x0800) -> bytes:
    return MAC_B + MAC_A + struct.pack("!H", ethertype) + payload


def ipv4(payload: bytes, proto: int, src: str = "10.0.0.1", dst: str = "10.0.0.2") -> bytes:
    return (
        struct.pack(
            "!BBHHHBBH4s4s",
            0x45,
            0,
            20 + len(payload),
            1,
            0x4000,
            64,
            proto,
            0,
            socket.inet_aton(src),
            socket.inet_aton(dst),
        )
        + payload
    )


def udp_frame(sport: int = 5000, dport: int = 5001, body: bytes = b"x") -> bytes:
    udp = struct.pack("!HHHH", sport, dport, 8 + len(body), 0) + body
    return ethernet(ipv4(udp, 17))


def tcp_frame(sport: int = 51234, dport: int = 443, flags: int = 0x02) -> bytes:
    tcp = struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 0x50, flags, 64240, 0, 0)
    return ethernet(ipv4(tcp, 6))


def icmp_frame() -> bytes:
    body = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"ping"
    return ethernet(ipv4(body, 1))


def make_packet(raw: bytes, index: int = 1) -> Packet:
    return Packet(
        index=index,
        ts=0.0,
        caplen=len(raw),
        wirelen=len(raw),
        linktype=1,
        raw=memoryview(raw),
    )


def matches(expression: str, raw: bytes) -> bool:
    packet = make_packet(raw)
    return compile_filter(expression).match(packet, decode_packet(packet))


# ---- 词法 ----
def test_tokenize_produces_eof() -> None:
    tokens = tokenize("ip.src == 10.0.0.1")
    assert tokens[-1].kind == "EOF"
    assert [token.kind for token in tokens[:3]] == ["IDENT", "OP", "IP"]


def test_tokenize_string_escape() -> None:
    token = tokenize(r'protocol == "a\"b"')[2]
    assert token.value == 'a"b'


def test_tokenize_unterminated_string_reports_position() -> None:
    with pytest.raises(FilterError) as excinfo:
        tokenize('protocol == "abc')
    assert "结束引号" in excinfo.value.message
    assert excinfo.value.position == 12


def test_tokenize_unknown_character() -> None:
    with pytest.raises(FilterError) as excinfo:
        tokenize("ip.src == 1 $")
    assert "无法识别" in excinfo.value.message


def test_tokenize_keyword_aliases() -> None:
    kinds = [token.kind for token in tokenize("a == 1 and b == 2")]
    assert "AND" in kinds


# ---- 语法 ----
def test_precedence_and_before_or() -> None:
    node = parse("ip.src == 10.0.0.1 || tcp.port == 80 && tcp.flags.syn == 1")
    assert isinstance(node, Or)
    assert isinstance(node.left, Compare)
    assert isinstance(node.right, And)


def test_parentheses_override_precedence() -> None:
    node = parse("(ip.src == 10.0.0.1 || tcp.port == 80) && tcp.flags.syn == 1")
    assert isinstance(node, And)
    assert isinstance(node.left, Or)


def test_not_is_unary() -> None:
    node = parse("!(ip.src == 10.0.0.1)")
    assert isinstance(node, Not)


def test_empty_expression_rejected() -> None:
    with pytest.raises(FilterError) as excinfo:
        parse("   ")
    assert "表达式为空" in excinfo.value.message


def test_missing_parenthesis() -> None:
    with pytest.raises(FilterError) as excinfo:
        parse("(ip.src == 10.0.0.1")
    assert "右括号" in excinfo.value.message


def test_trailing_content_rejected() -> None:
    with pytest.raises(FilterError):
        parse("ip.src == 10.0.0.1 ip.dst == 10.0.0.2")


# ---- 求值 ----
def test_ip_src_match() -> None:
    assert matches("ip.src == 10.0.0.1", udp_frame()) is True
    assert matches("ip.src == 10.0.0.9", udp_frame()) is False


def test_ip_dst_inequality() -> None:
    assert matches("ip.dst != 10.0.0.2", udp_frame()) is False
    assert matches("ip.dst != 10.0.0.3", udp_frame()) is True


def test_ip_addr_matches_either_side() -> None:
    assert matches("ip.addr == 10.0.0.2", udp_frame()) is True


def test_cidr_match() -> None:
    assert matches("ip.addr == 10.0.0.0/8", udp_frame()) is True
    assert matches("ip.addr == 192.168.0.0/16", udp_frame()) is False


def test_tcp_port_either_side() -> None:
    assert matches("tcp.port == 443", tcp_frame()) is True
    assert matches("tcp.port == 51234", tcp_frame()) is True


def test_tcp_dstport_is_directional() -> None:
    assert matches("tcp.dstport == 443", tcp_frame()) is True
    assert matches("tcp.srcport == 443", tcp_frame()) is False


def test_missing_field_never_matches() -> None:
    assert matches("tcp.port == 443", udp_frame()) is False
    assert matches("stream_id == 1", udp_frame()) is False


def test_tcp_flags_syn() -> None:
    assert matches("tcp.flags.syn == 1", tcp_frame(flags=0x02)) is True
    assert matches("tcp.flags.syn == 0", tcp_frame(flags=0x10)) is True


def test_icmp_type() -> None:
    assert matches("icmp.type == 8", icmp_frame()) is True
    assert matches("icmp.type == 0", icmp_frame()) is False


def test_ip_proto_accepts_name_and_number() -> None:
    assert matches("ip.proto == udp", udp_frame()) is True
    assert matches("ip.proto == 17", udp_frame()) is True
    assert matches("ip.proto == tcp", udp_frame()) is False


def test_protocol_is_case_insensitive() -> None:
    assert matches("protocol == udp", udp_frame()) is True
    assert matches("protocol == UDP", udp_frame()) is True
    assert matches("protocol == http", udp_frame()) is False


def test_frame_len_and_number() -> None:
    assert matches("frame.len > 40", udp_frame()) is True
    assert matches("frame.len < 40", udp_frame()) is False
    assert matches("frame.number == 1", udp_frame()) is True


def test_boolean_combination() -> None:
    expression = "protocol == udp && ip.src == 10.0.0.1 && udp.dstport == 5001"
    assert matches(expression, udp_frame()) is True
    assert matches("protocol == udp || protocol == icmp", icmp_frame()) is True


def test_negation() -> None:
    assert matches("!(protocol == icmp)", udp_frame()) is True
    assert matches("!(protocol == icmp)", icmp_frame()) is False


# ---- 类型与错误 ----
@pytest.mark.parametrize(
    "expression,keyword",
    [
        ("ip.srcc == 1", "未知字段"),
        ('tcp.port == "80"', "需要整数"),
        ("protocol == 80", "需要字符串"),
        ("ip.src < 1", "只支持"),
        ("ip.src == 10.0.0.999", "无法解析"),
        ("frame.len ==", "需要值"),
        ("tcp.port == 80 &&", "需要字段名"),
    ],
)
def test_compile_errors(expression: str, keyword: str) -> None:
    with pytest.raises(FilterError) as excinfo:
        compile_filter(expression)
    assert keyword in str(excinfo.value)


def test_error_message_contains_column() -> None:
    with pytest.raises(FilterError) as excinfo:
        compile_filter("ip.srcc == 1")
    assert str(excinfo.value).startswith("第 1 列")


def test_quoted_number_is_text() -> None:
    assert matches('protocol == "udp"', udp_frame()) is True
