"""轻量 DPI：按首载荷识别应用层协议。"""

from __future__ import annotations

from nps.decode.dpi.matcher import (
    CONFIDENCE_DPI,
    CONFIDENCE_PORT,
    PORT_HINTS,
    Signature,
    classify,
    load_signatures,
    match_payload,
)

__all__ = [
    "CONFIDENCE_DPI",
    "CONFIDENCE_PORT",
    "PORT_HINTS",
    "Signature",
    "classify",
    "load_signatures",
    "match_payload",
]
