"""UDP 解析。"""

from __future__ import annotations

from nps.decode.fields import Decoded, Field
from nps.decode.utils import u16


def decode(
    raw: bytes,
    offset: int,
    layers: list[Field],
    decoded: Decoded,
    payload_len: int,
) -> None:
    decoded.protocol = "UDP"
    if len(raw) < offset + 8:
        layers.append(Field("User Datagram Protocol", "truncated", offset, len(raw) - offset))
        decoded.summary = "truncated UDP header"
        return

    src_port = u16(raw, offset) or 0
    dst_port = u16(raw, offset + 2) or 0
    length = u16(raw, offset + 4) or 0
    checksum = u16(raw, offset + 6) or 0
    body = max(0, (length or payload_len) - 8)
    body = min(body, max(0, len(raw) - offset - 8))

    layer = Field(
        "User Datagram Protocol",
        f"Src Port: {src_port}, Dst Port: {dst_port}, Length: {length}",
        offset,
        8,
    )
    layer.add("Source Port", src_port, offset, 2)
    layer.add("Destination Port", dst_port, offset + 2, 2)
    layer.add("Length", length, offset + 4, 2)
    layer.add("Checksum", f"0x{checksum:04x}", offset + 6, 2)
    if body:
        layer.add("UDP payload", f"{body} bytes", offset + 8, body)
    layers.append(layer)

    decoded.put(
        **{
            "udp.srcport": src_port,
            "udp.dstport": dst_port,
            "udp.len": length,
        }
    )

    decoded.summary = f"{src_port} → {dst_port} Len={body}"
