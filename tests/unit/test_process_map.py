"""进程归属：快照匹配规则、TTL、降级与显示过滤字段。"""

from __future__ import annotations

import socket
import struct
from types import SimpleNamespace

import pytest

from nps.core.packet import Packet
from nps.core.process_map import (
    NullResolver,
    ProcessTable,
    SystemResolver,
)
from nps.decode import decode_packet
from nps.filters import FilterError, compile_filter

CLIENT = ("192.168.1.5", 50000)
SERVER = ("93.184.216.34", 443)


class Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


def test_exact_match_forward() -> None:
    table = ProcessTable()
    table.add(6, CLIENT, SERVER, 1234)

    info = table.match(CLIENT, SERVER, 6)
    assert info is not None
    assert info.pid == 1234
    assert info.confidence == "exact"


def test_exact_match_when_server_is_local() -> None:
    table = ProcessTable()
    server_local = ("192.168.1.5", 443)
    remote_client = ("10.0.0.9", 51000)
    table.add(6, server_local, remote_client, 777)

    info = table.match(remote_client, server_local, 6)
    assert info is not None
    assert info.pid == 777


def test_loopback_prefers_initiator() -> None:
    table = ProcessTable()
    client = ("127.0.0.1", 50000)
    server = ("127.0.0.1", 8080)
    table.add(6, client, server, 111)
    table.add(6, server, client, 222)

    info = table.match(client, server, 6)
    assert info is not None
    assert info.pid == 111


def test_port_fallback_for_listener() -> None:
    table = ProcessTable()
    listener = ("192.168.1.5", 8080)
    table.add(6, listener, ("0.0.0.0", 0), 333)

    info = table.match(("10.0.0.9", 51000), listener, 6)
    assert info is not None
    assert info.pid == 333
    assert info.confidence == "port"


def test_port_conflict_is_ambiguous() -> None:
    table = ProcessTable()
    table.add(6, ("192.168.1.5", 8080), ("0.0.0.0", 0), 333)
    table.add(6, ("192.168.1.5", 8080), ("0.0.0.0", 0), 444)

    info = table.match(("10.0.0.9", 51000), ("192.168.1.5", 8080), 6)
    assert info is not None
    assert info.pid is None
    assert info.confidence == "ambiguous"
    assert "共用" in info.note


def test_zero_pid_rows_are_ignored() -> None:
    # TIME_WAIT 等状态没有 owner，PID 为 0；归到 System Idle 属于误归属
    table = ProcessTable()
    table.add(6, ("192.168.1.5", 50000), ("93.184.216.34", 443), 0)

    assert len(table) == 0
    assert table.match(("192.168.1.5", 50000), ("93.184.216.34", 443), 6) is None


def test_wildcard_listener_port_fallback() -> None:
    table = ProcessTable()
    table.add(6, ("10.0.0.5", 50000), ("93.184.216.34", 443), 111)  # 注册本机地址
    table.add(6, ("0.0.0.0", 8080), ("0.0.0.0", 0), 222)  # 通配监听

    info = table.match(("8.8.8.8", 51000), ("10.0.0.5", 8080), 6)
    assert info is not None
    assert info.pid == 222
    assert info.confidence == "port"


def test_unknown_endpoints_return_none() -> None:
    table = ProcessTable()
    table.add(6, CLIENT, SERVER, 1234)

    assert table.match(("8.8.8.8", 1234), ("1.1.1.1", 80), 6) is None


def test_udp_connected_socket_matches() -> None:
    table = ProcessTable()
    table.add(17, ("192.168.1.5", 53000), ("8.8.8.8", 53), 900)

    info = table.match(("192.168.1.5", 53000), ("8.8.8.8", 53), 17)
    assert info is not None
    assert info.pid == 900


def test_system_resolver_ttl_and_name_cache(monkeypatch) -> None:
    table = ProcessTable()
    table.add(6, CLIENT, SERVER, 42)
    loads: list[int] = []

    def loader() -> ProcessTable:
        loads.append(1)
        return table

    names: list[int] = []

    def fake_name(pid: int) -> str:
        names.append(pid)
        return "python.exe"

    monkeypatch.setattr("nps.core.process_map._windows_process_name", fake_name)
    clock = Clock()
    resolver = SystemResolver(loader=loader, clock=clock, ttl=2.0)

    first = resolver.resolve(CLIENT, SERVER, 6)
    second = resolver.resolve(CLIENT, SERVER, 6)
    assert first is not None and second is not None
    assert first.pid == 42 and first.name == "python.exe"
    assert len(loads) == 1
    assert len(names) == 1  # 名称缓存命中

    clock.now = 3.0
    resolver.resolve(CLIENT, SERVER, 6)
    assert len(loads) == 2


def test_system_resolver_degrades_on_error() -> None:
    def broken() -> ProcessTable:
        raise OSError("access denied")

    resolver = SystemResolver(loader=broken)
    assert resolver.resolve(CLIENT, SERVER, 6) is None
    assert "读取失败" in resolver.status_text


def test_null_resolver() -> None:
    resolver = NullResolver()
    assert resolver.resolve(CLIENT, SERVER, 6) is None
    assert "不可用" in resolver.status_text


def _packet() -> Packet:
    tcp = struct.pack("!HHIIBBHHH", CLIENT[1], SERVER[1], 1, 0, 0x50, 0x18, 64240, 0, 0)
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        1,
        0x4000,
        64,
        6,
        0,
        socket.inet_aton(CLIENT[0]),
        socket.inet_aton(SERVER[0]),
    )
    frame = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp
    return Packet(
        index=1,
        ts=1.0,
        caplen=len(frame),
        wirelen=len(frame),
        linktype=1,
        raw=memoryview(frame),
    )


def test_process_filters_read_session_fields() -> None:
    packet = _packet()
    decoded = decode_packet(packet)
    session = SimpleNamespace(pid=1234, process_name="python.exe")

    assert compile_filter("process.pid == 1234").match(packet, decoded, session)
    assert compile_filter('process.name == "PYTHON.EXE"').match(packet, decoded, session)
    assert not compile_filter("process.pid == 1").match(packet, decoded, session)
    assert not compile_filter("process.pid == 1234").match(packet, decoded, None)


def test_process_filter_rejects_type_mismatch() -> None:
    with pytest.raises(FilterError, match="需要整数"):
        compile_filter('process.pid == "1234"')
