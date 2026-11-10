"""TCP 解析（不做重组，仅头部字段与载荷长度）。"""

from __future__ import annotations

from nps.decode.fields import Decoded, Field
from nps.decode.utils import format_tcp_flags, u16, u32


def decode(
    raw: bytes,
    offset: int,
    layers: list[Field],
    decoded: Decoded,
    payload_len: int,
) -> None:
    decoded.protocol = "TCP"
    if len(raw) < offset + 20:
        layers.append(
            Field("Transmission Control Protocol", "truncated", offset, len(raw) - offset)
        )
        decoded.summary = "truncated TCP header"
        return

    src_port = u16(raw, offset) or 0
    dst_port = u16(raw, offset + 2) or 0
    seq = u32(raw, offset + 4) or 0
    ack = u32(raw, offset + 8) or 0
    data_offset = (raw[offset + 12] >> 4) * 4
    if data_offset < 20:
        data_offset = 20
    flags = raw[offset + 13]
    window = u16(raw, offset + 14) or 0
    checksum = u16(raw, offset + 16) or 0
    urgent = u16(raw, offset + 18) or 0
    flag_text = format_tcp_flags(flags)
    body_len = max(0, payload_len - data_offset)

    layer = Field(
        "Transmission Control Protocol",
        f"Src Port: {src_port}, Dst Port: {dst_port}, Seq: {seq}, Ack: {ack}, Len: {body_len}",
        offset,
        data_offset,
    )
    layer.add("Source Port", src_port, offset, 2)
    layer.add("Destination Port", dst_port, offset + 2, 2)
    layer.add("Sequence Number", seq, offset + 4, 4)
    layer.add("Acknowledgment Number", ack, offset + 8, 4)
    layer.add("Header Length", f"{data_offset} bytes ({data_offset // 4})", offset + 12, 1)

    flags_node = layer.add("Flags", f"0x{flags:03x} ({flag_text})", offset + 13, 1)
    for name, bit in (
        ("FIN", 0x01),
        ("SYN", 0x02),
        ("RST", 0x04),
        ("PSH", 0x08),
        ("ACK", 0x10),
        ("URG", 0x20),
        ("ECE", 0x40),
        ("CWR", 0x80),
    ):
        flags_node.add(f"{name}", 1 if flags & bit else 0, offset + 13, 1)

    layer.add("Window", window, offset + 14, 2)
    layer.add("Checksum", f"0x{checksum:04x}", offset + 16, 2)
    layer.add("Urgent Pointer", urgent, offset + 18, 2)
    if body_len:
        layer.add("TCP payload", f"{body_len} bytes", offset + data_offset, body_len)
    layers.append(layer)

    decoded.put(
        **{
            "tcp.srcport": src_port,
            "tcp.dstport": dst_port,
            "tcp.flags": flags,
            "tcp.flags.syn": int(bool(flags & 0x02)),
            "tcp.flags.ack": int(bool(flags & 0x10)),
            "tcp.len": body_len,
        }
    )

    decoded.summary = (
        f"{src_port} → {dst_port} [{flag_text}] Seq={seq} Ack={ack} Win={window} Len={body_len}"
    )
