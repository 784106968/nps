"""性能基线：解析、会话归表、模型插入与流视图渲染。

用法::

    python scripts/bench.py                       # 1k / 10k / 100k
    python scripts/bench.py --sizes 1000,10000    # 指定规模
    python scripts/bench.py --json                # 机器可读输出
    python scripts/bench.py --repeat 5            # 每项取多次最小值

口径说明：
- 所有包使用同一五元组，流视图能拿到完整 1k/10k/100k 个点；
- 「解析」是 ``decode_packet`` 全量构树，最坏情况（列表里所有包都可见）；
- 「模型插入」含会话归表与 Qt 行插入，不含惰性解析；
- 「流渲染」是离屏 QPixmap 渲染一次，包含聚合策略；
- 内存用 tracemalloc 峰值，只覆盖包对象与原始字节，不含 Qt。
"""

from __future__ import annotations

import argparse
import json
import os
import struct
import sys
import time
import tracemalloc
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from PySide6.QtGui import QPixmap  # noqa: E402
from PySide6.QtWidgets import QApplication  # noqa: E402

from nps.core.buffer import BoundedPacketQueue  # noqa: E402
from nps.core.packet import Packet  # noqa: E402
from nps.core.session import SessionTable  # noqa: E402
from nps.decode import decode_packet  # noqa: E402
from nps.gui.detail_tree import DetailTree  # noqa: E402
from nps.gui.flow_view import FlowView  # noqa: E402
from nps.gui.packet_model import PacketTableModel  # noqa: E402

CLIENT_IP = b"\x0a\x00\x00\x01"
SERVER_IP = b"\x5d\xb8\xd8\x22"
PAYLOAD = b"x" * 32
QUEUE_CAPACITY = 100_000
CHART_SIZE = (1200, 500)


def build_frame(seq: int) -> bytes:
    tcp = (
        struct.pack(
            "!HHIIBBHHH",
            51234,
            80,
            seq & 0xFFFFFFFF,
            0,
            0x50,
            0x18,
            64240,
            0,
            0,
        )
        + PAYLOAD
    )
    ip = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(tcp),
        seq & 0xFFFF,
        0x4000,
        64,
        6,
        0,
        CLIENT_IP,
        SERVER_IP,
    )
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp


def build_packets(count: int) -> list[Packet]:
    packets: list[Packet] = []
    for index in range(count):
        frame = build_frame(index)
        packets.append(
            Packet(
                index=index + 1,
                ts=1_000.0 + index * 0.001,
                caplen=len(frame),
                wirelen=len(frame),
                linktype=1,
                raw=memoryview(frame),
            )
        )
    return packets


def measure(action, repeat: int) -> float:
    best = float("inf")
    for _ in range(max(1, repeat)):
        started = time.perf_counter()
        action()
        best = min(best, time.perf_counter() - started)
    return best * 1000.0


def bench_size(size: int, repeat: int) -> dict:
    packets = build_packets(size)

    started = time.perf_counter()
    decoded = [decode_packet(packet) for packet in packets]
    decode_ms = (time.perf_counter() - started) * 1000.0
    assert len(decoded) == size

    session_ms = measure(lambda: _feed_sessions(packets), repeat)
    table = SessionTable()
    for packet in packets:
        table.add(packet)

    model_ms = measure(
        lambda: PacketTableModel(capacity=max(size * 2, 1_000)).append_batch(packets),
        repeat,
    )

    session = table.get(1)
    view = FlowView()
    view.resize(*CHART_SIZE)
    flow_build_ms = measure(lambda: view.set_flow(session, packets), repeat)

    pixmap = QPixmap(*CHART_SIZE)
    view.render(pixmap)
    flow_render_ms = measure(lambda: view.render(pixmap), repeat)

    tree = DetailTree()
    layers = decode_packet(packets[0]).layers
    detail_ms = measure(lambda: tree.show_layers(layers), repeat)

    return {
        "packets": size,
        "decode_ms": round(decode_ms, 2),
        "decode_per_sec": round(size / (decode_ms / 1000.0)) if decode_ms else 0,
        "session_ms": round(session_ms, 2),
        "model_ms": round(model_ms, 2),
        "flow_build_ms": round(flow_build_ms, 2),
        "flow_render_ms": round(flow_render_ms, 2),
        "flow_points": view.point_count(),
        "detail_ms": round(detail_ms, 2),
    }


def _feed_sessions(packets: list[Packet]) -> None:
    table = SessionTable()
    for packet in packets:
        table.add(packet)


def measure_memory(size: int) -> float:
    tracemalloc.start()
    packets = build_packets(size)
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()
    assert packets
    return peak / (1024 * 1024)


def bench_queue(size: int) -> dict:
    queue = BoundedPacketQueue(QUEUE_CAPACITY)
    packets = build_packets(QUEUE_CAPACITY + size)
    started = time.perf_counter()
    for packet in packets:
        queue.put(packet)
    elapsed_ms = (time.perf_counter() - started) * 1000.0
    return {
        "capacity": QUEUE_CAPACITY,
        "pushed": len(packets),
        "dropped": queue.dropped,
        "elapsed_ms": round(elapsed_ms, 2),
    }


def format_markdown(results: list[dict], memory: dict[int, float], queue: dict) -> str:
    lines = [
        "| 包数 | 解析 (ms) | 解析 (包/秒) | 会话归表 (ms) | 模型插入 (ms) "
        "| 流构建 (ms) | 流渲染 (ms) | 详情树 (ms) | 峰值内存 (MB) |",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for row in results:
        size = row["packets"]
        lines.append(
            "| {packets} | {decode_ms} | {decode_per_sec} | {session_ms} | {model_ms} | "
            "{flow_build_ms} | {flow_render_ms} | {detail_ms} | {memory:.1f} |".format(
                memory=memory[size], **row
            )
        )
    lines.append("")
    lines.append(
        "队列：容量 {capacity}，灌入 {pushed}，丢弃 {dropped}，耗时 {elapsed_ms} ms".format(**queue)
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="bench", description="NPS 性能基线")
    parser.add_argument("--sizes", default="1000,10000,100000", help="逗号分隔的包数")
    parser.add_argument("--repeat", type=int, default=3, help="每项重复次数，取最小值")
    parser.add_argument("--json", action="store_true", help="输出 JSON")
    args = parser.parse_args(argv)

    sizes = [int(item) for item in args.sizes.split(",") if item.strip()]
    QApplication.instance() or QApplication([])

    print(f"NPS bench  python {sys.version.split()[0]} / {sys.platform}")
    results = [bench_size(size, args.repeat) for size in sizes]
    memory = {size: measure_memory(size) for size in sizes}
    queue = bench_queue(sizes[-1])

    if args.json:
        print(json.dumps({"results": results, "memory_mb": memory, "queue": queue}, indent=2))
    else:
        print(format_markdown(results, memory, queue))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
