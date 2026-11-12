"""进程归属自检：验证 Windows 连接表与进程名读取是否可用。

用法::

    python scripts/probe_process.py
    python scripts/probe_process.py --pid 1234
    python scripts/probe_process.py --limit 20

输出当前快照规模、刷新耗时，并列出本进程或指定 PID 的连接。
不抓包、不需要 Npcap，可在开发机上单独验证 OS 接口。
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from nps.core.process_map import SystemResolver, create_resolver  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="probe_process", description="NPS 进程归属自检")
    parser.add_argument("--pid", type=int, default=os.getpid(), help="要列出的 PID，默认当前进程")
    parser.add_argument("--limit", type=int, default=10, help="最多列出多少条连接")
    args = parser.parse_args(argv)

    resolver = create_resolver()
    if not isinstance(resolver, SystemResolver):
        print(f"不可用：{resolver.status_text}")
        return 1

    resolver.refresh(force=True)
    table = resolver.table
    if table is None:
        print(f"读取失败：{resolver.status_text}")
        return 1

    print(f"状态：{resolver.status_text}")
    print(f"快照：{len(table)} 条精确连接，{len(table.local_addrs)} 个本机地址")
    print(f"刷新耗时：{resolver.last_refresh_ms:.1f} ms")

    rows = [(key, info) for key, info in table.exact.items() if info.pid == args.pid]
    rows.sort(key=lambda item: item[0][2])
    print(f"PID {args.pid} 的连接：{len(rows)} 条")
    for key, _ in rows[: args.limit]:
        proto, local_ip, local_port, remote_ip, remote_port = key
        name = resolver.resolve((local_ip, local_port), (remote_ip, remote_port), proto)
        label = name.name if name else "-"
        print(
            f"  {'TCP' if proto == 6 else 'UDP'}  {local_ip}:{local_port} -> "
            f"{remote_ip}:{remote_port}  {label}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
