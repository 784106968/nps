"""包摘要模型。

设计约束（见 NPS-Readme.md §3.2）：
- ``raw`` 保存原始字节的只读视图，供十六进制视图、导出与二次解析复用，不做深拷贝；
- ``layers`` 作为解析结果缓存，首次解析后填充，避免重复解析；
- ``index`` 是全局单调序号，显示过滤后仍保留原值。
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass
from typing import Any

_HEX_LIMIT = 32


@dataclass(slots=True)
class Packet:
    index: int
    ts: float
    caplen: int
    wirelen: int
    linktype: int
    raw: memoryview
    layers: dict[str, Any] | None = None
    stream_id: int | None = None
    protocol: str | None = None
    confidence: str | None = None

    @property
    def truncated(self) -> bool:
        """抓包长度小于线路长度，说明被 snaplen 截断。"""
        return self.caplen < self.wirelen

    @property
    def network_offset(self) -> int | None:
        """三层头部在本帧中的偏移；无法识别的链路类型返回 None。

        Npcap 的回环适配器上报 DLT_NULL（4 字节地址族），而不是以太网，
        因此解析前必须先看链路类型，不能一律按 14 字节以太网头处理。
        """
        if self.linktype == 1:  # DLT_EN10MB
            return 14
        if self.linktype == 0:  # DLT_NULL
            return 4
        if self.linktype in (12, 101):  # DLT_RAW
            return 0
        if self.linktype == 113:  # DLT_LINUX_SLL
            return 16
        return None

    @property
    def ts_text(self) -> str:
        moment = _dt.datetime.fromtimestamp(self.ts)
        return moment.strftime("%H:%M:%S.%f")[:-3]

    def head_hex(self, limit: int = _HEX_LIMIT) -> str:
        data = bytes(self.raw[:limit])
        return data.hex(" ")

    def __str__(self) -> str:  # pragma: no cover - 仅用于调试输出
        return f"Packet(index={self.index}, caplen={self.caplen}, wirelen={self.wirelen})"
