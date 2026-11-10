"""最小 PCAP 写入实现。

只写经典 libpcap 格式（magic 0xa1b2c3d4、微秒精度），保证产物能被 Wireshark、
tcpdump 与本项目自身读取。包目录（pcapng）不在本期范围。
"""

from __future__ import annotations

import struct
from collections.abc import Iterable
from pathlib import Path

from nps.core.packet import Packet

PCAP_MAGIC = 0xA1B2C3D4
VERSION_MAJOR = 2
VERSION_MINOR = 4
SNAPLEN = 65535


def write_pcap(path: str | Path, packets: Iterable[Packet], linktype: int | None = None) -> int:
    """写入 PCAP，返回写入的包数。

    链路类型缺省取第一个包的；同一文件内混用不同链路类型本身就不合法，
    因此不做逐包转换。
    """
    items = list(packets)
    if not items and linktype is None:
        raise ValueError("没有可写的数据包，且未指定链路类型")

    resolved = linktype if linktype is not None else items[0].linktype
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)

    with target.open("wb") as handle:
        handle.write(
            struct.pack(
                "<IHHiIII",
                PCAP_MAGIC,
                VERSION_MAJOR,
                VERSION_MINOR,
                0,
                0,
                SNAPLEN,
                resolved,
            )
        )
        for packet in items:
            seconds = int(packet.ts)
            microseconds = int(round((packet.ts - seconds) * 1_000_000))
            if microseconds >= 1_000_000:
                seconds += 1
                microseconds -= 1_000_000
            handle.write(
                struct.pack(
                    "<IIII",
                    seconds,
                    microseconds,
                    packet.caplen,
                    packet.wirelen,
                )
            )
            handle.write(bytes(packet.raw))
    return len(items)


def read_pcap_header(path: str | Path) -> tuple[int, int]:
    """读取全局头，返回 (链路类型, 魔数)，供测试与格式校验使用。"""
    with Path(path).open("rb") as handle:
        raw = handle.read(24)
    if len(raw) < 24:
        raise ValueError("PCAP 文件过短")
    magic, _, _, _, _, _, linktype = struct.unpack("<IHHiIII", raw)
    return linktype, magic
