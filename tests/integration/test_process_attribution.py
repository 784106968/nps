"""真实连接上的进程归属验证（Windows）。

不依赖 Npcap：只读 Windows 连接表，建立本机回环连接即可验证。
Linux 本期不实现，整个模块跳过。
"""

from __future__ import annotations

import os
import socket
import struct
import sys

import pytest

from nps.core.packet import Packet
from nps.core.process_map import SystemResolver
from nps.core.session import SessionTable

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="进程归属当前仅支持 Windows")


def _resolver() -> SystemResolver:
    resolver = SystemResolver()
    resolver.refresh(force=True)
    return resolver


def test_tcp_loopback_attribution() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.create_connection(listener.getsockname(), timeout=3)
    server, _ = listener.accept()
    try:
        info = _resolver().resolve(client.getsockname(), client.getpeername(), 6)
        assert info is not None
        assert info.pid == os.getpid()
        assert info.confidence == "exact"
        assert info.name
    finally:
        client.close()
        server.close()
        listener.close()


def test_tcp_server_side_attribution() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.create_connection(listener.getsockname(), timeout=3)
    server, _ = listener.accept()
    try:
        # 从服务端视角查询同一连接，也应归到本进程
        info = _resolver().resolve(server.getsockname(), server.getpeername(), 6)
        assert info is not None
        assert info.pid == os.getpid()
    finally:
        client.close()
        server.close()
        listener.close()


def test_udp_port_attribution() -> None:
    receiver = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    receiver.bind(("127.0.0.1", 0))
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.connect(receiver.getsockname())
    try:
        info = _resolver().resolve(sender.getsockname(), receiver.getsockname(), 17)
        assert info is not None
        assert info.pid == os.getpid()
        assert info.confidence in {"exact", "port"}
    finally:
        sender.close()
        receiver.close()


def test_unknown_connection_returns_none() -> None:
    resolver = _resolver()
    assert resolver.resolve(("127.0.0.1", 65000), ("127.0.0.1", 65001), 6) is None


def test_session_table_attributes_real_connection() -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.create_connection(listener.getsockname(), timeout=3)
    server, _ = listener.accept()
    try:
        local, remote = client.getsockname(), client.getpeername()
        tcp = struct.pack("!HHIIBBHHH", local[1], remote[1], 1, 0, 0x50, 0x02, 64240, 0, 0)
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
            socket.inet_aton(local[0]),
            socket.inet_aton(remote[0]),
        )
        frame = b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp
        packet = Packet(
            index=1,
            ts=1.0,
            caplen=len(frame),
            wirelen=len(frame),
            linktype=1,
            raw=memoryview(frame),
        )

        table = SessionTable(resolver=SystemResolver())
        session = table.add(packet)
        assert session is not None
        assert session.pid == os.getpid()
        assert session.process_confidence == "exact"
        assert session.process_name
    finally:
        client.close()
        server.close()
        listener.close()
