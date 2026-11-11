"""基于首载荷的轻量 DPI。

只做"这一层载荷像不像某协议"，不做完整解析：
- 端口只作初筛，置信度标为 ``port``；
- 命中签名后升级为 ``dpi``；
- 两者都拿不到就返回空，界面显示传输层协议。

这样既能识别 80 端口上的 HTTP，也能识别跑在 8080/随机端口上的 HTTP。
"""

from __future__ import annotations

import functools
import json
from dataclasses import dataclass
from pathlib import Path

SIGNATURE_PATH = Path(__file__).with_name("signatures.json")

CONFIDENCE_DPI = "dpi"
CONFIDENCE_PORT = "port"

# 端口启发式：只用来给个初判，命中后仍可能被 DPI 覆盖
PORT_HINTS: dict[int, str] = {
    80: "HTTP",
    8080: "HTTP",
    8000: "HTTP",
    443: "TLS",
    8443: "TLS",
    22: "SSH",
    53: "DNS",
    6881: "BitTorrent",
    6882: "BitTorrent",
    6883: "BitTorrent",
    6884: "BitTorrent",
}


@dataclass(frozen=True, slots=True)
class Signature:
    protocol: str
    direction: str
    offset: int
    pattern: bytes
    description: str
    kind: str = "text"


def _decode_pattern(raw: str, kind: str) -> bytes:
    if kind == "hex":
        return bytes.fromhex(raw)
    return raw.encode("utf-8")


@functools.lru_cache(maxsize=4)
def load_signatures(path: str | None = None) -> tuple[Signature, ...]:
    target = Path(path) if path else SIGNATURE_PATH
    data = json.loads(target.read_text(encoding="utf-8"))
    signatures = []
    for rule in data.get("rules", []):
        kind = rule.get("kind", "text")
        signatures.append(
            Signature(
                protocol=rule["protocol"],
                direction=rule.get("direction", "any"),
                offset=int(rule.get("offset", 0)),
                pattern=_decode_pattern(rule.get("pattern", ""), kind),
                description=rule.get("description", ""),
                kind=kind,
            )
        )
    return tuple(signatures)


def _is_dns_query(payload: bytes) -> bool:
    if len(payload) < 17:
        return False
    flags = int.from_bytes(payload[2:4], "big")
    if flags & 0x8000:  # QR=1 表示响应，不是查询
        return False
    qdcount = int.from_bytes(payload[4:6], "big")
    if qdcount != 1:
        return False

    index = 12
    labels = 0
    while index < len(payload):
        length = payload[index]
        if length == 0:
            break
        if length > 63 or index + 1 + length > len(payload):
            return False
        index += 1 + length
        labels += 1
    else:
        return False
    if labels == 0:
        return False
    return index + 5 <= len(payload)


def match_payload(payload: bytes | None, direction: str) -> Signature | None:
    if not payload:
        return None
    for signature in load_signatures():
        if signature.direction not in ("any", direction):
            continue
        if signature.kind == "dns_query":
            if _is_dns_query(payload):
                return signature
            continue
        if not signature.pattern:
            continue
        if signature.kind == "contains":
            if signature.pattern in payload:
                return signature
            continue
        start = signature.offset
        end = start + len(signature.pattern)
        if len(payload) < end:
            continue
        if payload[start:end] == signature.pattern:
            return signature
    return None


def classify(
    uplink: bytes | None,
    downlink: bytes | None,
    sport: int,
    dport: int,
    proto: int,
) -> tuple[str | None, str | None, str]:
    """返回 (协议, 置信度, 依据说明)。"""
    matched = match_payload(uplink, "uplink") or match_payload(downlink, "downlink")
    if matched is not None:
        return matched.protocol, CONFIDENCE_DPI, matched.description

    port = dport or sport
    hint = PORT_HINTS.get(dport) or PORT_HINTS.get(sport)
    if hint:
        return hint, CONFIDENCE_PORT, f"端口 {port} 推断"
    return None, None, ""
