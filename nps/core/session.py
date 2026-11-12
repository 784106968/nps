"""会话表与流追踪。

- **规范化五元组**：两个端点按 ``(ip, port)`` 排序后拼成键，双向流量落在同一会话；
- **stream_id** 从 1 单调递增，首次建表时的首包方向记为 ``initiator``，据此判定上下行；
- **不做 TCP 重组**：只记录首上行载荷（≤512 字节）供后续 DPI 使用；
- **老化用显式时间**（``expire(now)``），便于用虚拟时钟写单元测试。

这里刻意不复用 ``nps.decode`` 的字段树：抓包线程每包都要建会话，
只需要 IPv4/IPv6 + L4 端口这几个偏移，独立做一次轻量解析比构树快得多。
"""

from __future__ import annotations

import ipaddress
import socket
from collections import OrderedDict
from dataclasses import dataclass, field

from nps.core.packet import Packet
from nps.core.process_map import NullResolver, ProcessResolver
from nps.decode.dpi.matcher import CONFIDENCE_DPI, classify

TCP = 6
UDP = 17
ICMP = 1
ICMPV6 = 58

PROTOCOL_NAMES = {TCP: "TCP", UDP: "UDP", ICMP: "ICMP", ICMPV6: "ICMPv6"}

DEFAULT_TIMEOUTS = {TCP: 120.0, UDP: 60.0, ICMP: 30.0, ICMPV6: 30.0}
OTHER_TIMEOUT = 60.0
MAX_PAYLOAD = 512


@dataclass(frozen=True, slots=True)
class FlowInfo:
    proto: int
    src: str
    dst: str
    sport: int
    dport: int
    payload_offset: int
    payload_len: int
    tcp_flags: int = 0


@dataclass(slots=True)
class Session:
    stream_id: int
    proto: int
    endpoint_a: tuple[str, int]
    endpoint_b: tuple[str, int]
    initiator: tuple[str, int]
    first_ts: float
    last_ts: float
    protocol: str
    packets_up: int = 0
    packets_down: int = 0
    bytes_up: int = 0
    bytes_down: int = 0
    tcp_flags: set[str] = field(default_factory=set)
    first_uplink_payload: bytes | None = None
    first_downlink_payload: bytes | None = None
    state: str = "active"
    pid: int | None = None
    process_name: str | None = None
    process_confidence: str | None = None  # "exact" | "port" | "ambiguous"
    process_note: str = ""
    app_protocol: str | None = None
    confidence: str | None = None
    classification_note: str = ""

    @property
    def duration(self) -> float:
        return max(0.0, self.last_ts - self.first_ts)

    @property
    def packets_total(self) -> int:
        return self.packets_up + self.packets_down

    @property
    def bytes_total(self) -> int:
        return self.bytes_up + self.bytes_down

    @property
    def client(self) -> tuple[str, int]:
        return self.initiator

    @property
    def server(self) -> tuple[str, int]:
        return self.endpoint_b if self.initiator == self.endpoint_a else self.endpoint_a

    @property
    def label(self) -> str:
        client_ip, client_port = self.client
        server_ip, server_port = self.server
        if self.proto in (ICMP, ICMPV6):
            return f"{client_ip} ↔ {server_ip}"
        return f"{client_ip}:{client_port} ↔ {server_ip}:{server_port}"


def _parse_flow(packet: Packet) -> FlowInfo | None:
    raw = packet.raw
    offset = packet.network_offset
    if offset is None or len(raw) < offset + 20:
        return None

    version = raw[offset] >> 4
    if version == 4:
        ihl = (raw[offset] & 0x0F) * 4
        if ihl < 20 or len(raw) < offset + ihl:
            ihl = 20
        proto = raw[offset + 9]
        total_len = int.from_bytes(raw[offset + 2 : offset + 4], "big")
        src = socket.inet_ntoa(raw[offset + 12 : offset + 16])
        dst = socket.inet_ntoa(raw[offset + 16 : offset + 20])
        l4 = offset + ihl
        segment_end = min(len(raw), offset + total_len) if total_len else len(raw)
    elif version == 6:
        if len(raw) < offset + 40:
            return None
        proto = raw[offset + 6]
        payload_len = int.from_bytes(raw[offset + 4 : offset + 6], "big")
        # Python 3.12 的 IPv6Address 只接受 bytes，memoryview 会被当成字符串解析
        src = str(ipaddress.IPv6Address(bytes(raw[offset + 8 : offset + 24])))
        dst = str(ipaddress.IPv6Address(bytes(raw[offset + 24 : offset + 40])))
        l4 = offset + 40
        segment_end = min(len(raw), l4 + payload_len)
    else:
        return None

    sport = dport = 0
    flags = 0
    payload_offset = l4
    if proto == TCP:
        if len(raw) < l4 + 20:
            return None
        sport = int.from_bytes(raw[l4 : l4 + 2], "big")
        dport = int.from_bytes(raw[l4 + 2 : l4 + 4], "big")
        data_offset = (raw[l4 + 12] >> 4) * 4
        if data_offset < 20:
            data_offset = 20
        flags = raw[l4 + 13]
        payload_offset = l4 + data_offset
    elif proto == UDP:
        if len(raw) < l4 + 8:
            return None
        sport = int.from_bytes(raw[l4 : l4 + 2], "big")
        dport = int.from_bytes(raw[l4 + 2 : l4 + 4], "big")
        payload_offset = l4 + 8
    elif proto in (ICMP, ICMPV6):
        payload_offset = l4
    else:
        return None

    payload_len = max(0, segment_end - payload_offset)
    payload_len = min(payload_len, len(raw) - payload_offset)
    return FlowInfo(
        proto=proto,
        src=src,
        dst=dst,
        sport=sport,
        dport=dport,
        payload_offset=payload_offset,
        payload_len=payload_len,
        tcp_flags=flags,
    )


_FLAG_NAMES = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
)

# 流视图需要判断每个包的方向（源端点是否等于 initiator），
# 公开别名避免跨模块引用私有函数。
parse_flow = _parse_flow


class SessionTable:
    """按 LRU 淘汰的会话表。"""

    def __init__(
        self,
        capacity: int = 20_000,
        resolver: ProcessResolver | None = None,
    ) -> None:
        if capacity <= 0:
            raise ValueError("capacity 必须为正整数")
        self._capacity = capacity
        self._resolver = resolver or NullResolver()
        self._sessions: OrderedDict[tuple[object, ...], Session] = OrderedDict()
        self._by_id: dict[int, Session] = {}
        self._next_id = 1
        self._evicted = 0
        self._expired = 0
        self._version = 0
        self._snapshot: list[Session] | None = None

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def version(self) -> int:
        """每次会话内容变化时自增，供界面模型做 O(1) 变更判断。"""
        return self._version

    @property
    def evicted(self) -> int:
        return self._evicted

    @property
    def expired(self) -> int:
        return self._expired

    def __len__(self) -> int:
        return len(self._sessions)

    def get(self, stream_id: int) -> Session | None:
        return self._by_id.get(stream_id)

    def sessions(self) -> list[Session]:
        """当前会话快照（只读；调用方不得修改返回列表）。"""
        if self._snapshot is None:
            self._snapshot = list(self._sessions.values())
        return self._snapshot

    def clear(self) -> None:
        self._sessions.clear()
        self._by_id.clear()
        self._next_id = 1
        self._evicted = 0
        self._expired = 0
        self._version += 1
        self._snapshot = None

    def add(self, packet: Packet) -> Session | None:
        """把包归入会话，并写回 ``packet.stream_id``；非 IP 包返回 None。"""
        flow = _parse_flow(packet)
        if flow is None:
            return None

        endpoint_src = (flow.src, flow.sport)
        endpoint_dst = (flow.dst, flow.dport)
        first, second = sorted((endpoint_src, endpoint_dst))
        key = (flow.proto, first, second)

        session = self._sessions.get(key)
        created = session is None
        if session is None:
            session = Session(
                stream_id=self._next_id,
                proto=flow.proto,
                endpoint_a=first,
                endpoint_b=second,
                initiator=endpoint_src,
                first_ts=packet.ts,
                last_ts=packet.ts,
                protocol=PROTOCOL_NAMES.get(flow.proto, f"IP/{flow.proto}"),
            )
            self._next_id += 1
            app, confidence, note = classify(None, None, 0, session.server[1], session.proto)
            session.app_protocol = app
            session.confidence = confidence
            session.classification_note = note
            self._sessions[key] = session
            self._by_id[session.stream_id] = session
            self._enforce_capacity()
        else:
            self._sessions.move_to_end(key)
            session.last_ts = max(session.last_ts, packet.ts)

        new_payload = self._absorb(session, packet, flow, endpoint_src)
        if created or (new_payload and session.process_confidence != "exact"):
            # 服务端 accept 后连接会从 listener 转移到 worker，首载荷时补一次精确归属
            self._attribute(session, endpoint_src, endpoint_dst, flow.proto)
        packet.stream_id = session.stream_id
        self._version += 1
        self._snapshot = None
        return session

    def _attribute(
        self,
        session: Session,
        src: tuple[str, int],
        dst: tuple[str, int],
        proto: int,
    ) -> None:
        try:
            info = self._resolver.resolve(src, dst, proto)
        except Exception:  # 归属失败不得影响会话主流程
            return
        if info is None:
            return
        session.pid = info.pid
        session.process_name = info.name or None
        session.process_confidence = info.confidence
        session.process_note = info.note

    def _absorb(self, session: Session, packet: Packet, flow: FlowInfo, endpoint_src) -> bool:
        up = endpoint_src == session.initiator
        if up:
            session.packets_up += 1
            session.bytes_up += packet.wirelen
        else:
            session.packets_down += 1
            session.bytes_down += packet.wirelen

        if flow.proto == TCP and flow.tcp_flags:
            for bit, name in _FLAG_NAMES:
                if flow.tcp_flags & bit:
                    session.tcp_flags.add(name)
            if flow.tcp_flags & 0x04:  # RST
                session.state = "closed"
            elif {"FIN", "ACK"} <= session.tcp_flags and flow.tcp_flags & 0x01:
                session.state = "closing"

        new_payload = False
        if flow.payload_len > 0:
            take = min(flow.payload_len, MAX_PAYLOAD)
            payload = bytes(packet.raw[flow.payload_offset : flow.payload_offset + take])
            if up and session.first_uplink_payload is None:
                session.first_uplink_payload = payload
                new_payload = True
            elif not up and session.first_downlink_payload is None:
                session.first_downlink_payload = payload
                new_payload = True

        # 端口初判可以被 DPI 覆盖；已经由签名确认过的就不再重算
        if new_payload and session.confidence != CONFIDENCE_DPI:
            app, confidence, note = classify(
                session.first_uplink_payload,
                session.first_downlink_payload,
                0,
                session.server[1],
                session.proto,
            )
            if app:
                session.app_protocol = app
                session.confidence = confidence
                session.classification_note = note
        return new_payload

    def _enforce_capacity(self) -> None:
        while len(self._sessions) > self._capacity:
            _, session = self._sessions.popitem(last=False)
            self._by_id.pop(session.stream_id, None)
            self._evicted += 1

    def expire(self, now: float) -> int:
        """按协议空闲超时清理会话，返回清理数量。"""
        if not self._sessions:
            return 0
        stale: list[tuple[object, ...]] = []
        for key, session in self._sessions.items():
            timeout = DEFAULT_TIMEOUTS.get(session.proto, OTHER_TIMEOUT)
            if now - session.last_ts >= timeout:
                stale.append(key)
        for key in stale:
            session = self._sessions.pop(key)
            self._by_id.pop(session.stream_id, None)
            self._expired += 1
        if stale:
            self._version += 1
            self._snapshot = None
        return len(stale)
