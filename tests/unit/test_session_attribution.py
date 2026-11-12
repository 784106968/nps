"""会话表与进程归属的集成：创建时归属、首载荷刷新、异常降级。"""

from __future__ import annotations

import socket
import struct

from nps.core.packet import Packet
from nps.core.process_map import ProcessInfo
from nps.core.session import SessionTable

CLIENT = ("10.0.0.1", 51234)
SERVER = ("93.184.216.34", 80)

_seq = 0


def _packet(frame: bytes, ts: float) -> Packet:
    global _seq
    _seq += 1
    return Packet(
        index=_seq,
        ts=ts,
        caplen=len(frame),
        wirelen=len(frame),
        linktype=1,
        raw=memoryview(frame),
    )


def _ipv4(payload: bytes, proto: int, src: str, dst: str) -> bytes:
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


def _eth(payload: bytes) -> bytes:
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + payload


def tcp_packet(
    src: tuple[str, int],
    dst: tuple[str, int],
    flags: int,
    payload: bytes = b"",
    ts: float = 1_000.0,
) -> Packet:
    tcp = struct.pack("!HHIIBBHHH", src[1], dst[1], 1, 0, 0x50, flags, 64240, 0, 0) + payload
    return _packet(_eth(_ipv4(tcp, 6, src[0], dst[0])), ts)


def udp_packet(
    src: tuple[str, int], dst: tuple[str, int], payload: bytes = b"x", ts: float = 1_000.0
) -> Packet:
    udp = struct.pack("!HHHH", src[1], dst[1], 8 + len(payload), 0) + payload
    return _packet(_eth(_ipv4(udp, 17, src[0], dst[0])), ts)


class FakeResolver:
    status_text = "测试解析器"

    def __init__(self, info: ProcessInfo | None = None, error: Exception | None = None) -> None:
        self.info = info
        self.error = error
        self.calls = 0

    def resolve(self, local, remote, proto) -> ProcessInfo | None:
        self.calls += 1
        if self.error is not None:
            raise self.error
        return self.info


class SequenceResolver:
    status_text = "序列解析器"

    def __init__(self, infos: list[ProcessInfo]) -> None:
        self.infos = infos
        self.calls = 0

    def resolve(self, local, remote, proto) -> ProcessInfo | None:
        self.calls += 1
        return self.infos[min(self.calls - 1, len(self.infos) - 1)]


def test_new_session_gets_process_attribution() -> None:
    resolver = FakeResolver(ProcessInfo(1234, "python.exe", "exact"))
    table = SessionTable(resolver=resolver)

    session = table.add(tcp_packet(CLIENT, SERVER, 0x02))
    assert session is not None
    assert session.pid == 1234
    assert session.process_name == "python.exe"
    assert session.process_confidence == "exact"
    assert resolver.calls == 1


def test_payload_refreshes_port_guess_to_exact() -> None:
    resolver = SequenceResolver(
        [
            ProcessInfo(100, "chrome.exe", "port", "仅按本地端口匹配"),
            ProcessInfo(200, "chrome.exe", "exact"),
        ]
    )
    table = SessionTable(resolver=resolver)

    session = table.add(tcp_packet(CLIENT, SERVER, 0x02))
    assert session is not None
    assert session.process_confidence == "port"

    session = table.add(tcp_packet(CLIENT, SERVER, 0x18, b"GET / HTTP/1.1\r\n", ts=1_000.1))
    assert session is not None
    assert session.pid == 200
    assert session.process_confidence == "exact"

    # 已经是 exact，后续载荷不再重复查询
    before = resolver.calls
    table.add(tcp_packet(SERVER, CLIENT, 0x18, b"HTTP/1.1 200 OK\r\n", ts=1_000.2))
    assert resolver.calls == before


def test_udp_session_can_be_attributed() -> None:
    resolver = FakeResolver(ProcessInfo(300, "dns.exe", "port", "仅按本地端口匹配"))
    table = SessionTable(resolver=resolver)

    session = table.add(udp_packet(CLIENT, ("8.8.8.8", 53)))
    assert session is not None
    assert session.pid == 300
    assert session.process_confidence == "port"


def test_ambiguous_keeps_pid_empty() -> None:
    resolver = FakeResolver(ProcessInfo(None, "", "ambiguous", "端口冲突"))
    table = SessionTable(resolver=resolver)

    session = table.add(tcp_packet(CLIENT, SERVER, 0x02))
    assert session is not None
    assert session.pid is None
    assert session.process_confidence == "ambiguous"
    assert session.process_note == "端口冲突"


def test_resolver_failure_does_not_break_session() -> None:
    resolver = FakeResolver(error=OSError("access denied"))
    table = SessionTable(resolver=resolver)

    session = table.add(tcp_packet(CLIENT, SERVER, 0x02))
    assert session is not None
    assert session.pid is None
    assert session.process_confidence is None


def test_null_resolver_is_default() -> None:
    table = SessionTable()
    session = table.add(tcp_packet(CLIENT, SERVER, 0x02))
    assert session is not None
    assert session.pid is None
