"""进程归属接口（本期仅占位）。

把 TCP 连接映射到发起进程需要使用操作系统接口：
Windows 走 ``GetExtendedTcpTable``，Linux 走 ``sock_diag`` + ``/proc/<pid>/fd``。
本期不实现，只保留接口与空实现，避免以后改会话模型（见 NPS-Readme.md §3.6）。
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable


@runtime_checkable
class ProcessResolver(Protocol):
    """把 (本地端点, 远端端点, 协议) 解析为进程。"""

    def resolve(
        self, local: tuple[str, int], remote: tuple[str, int], proto: int
    ) -> tuple[int, str] | None: ...


class NullResolver:
    """空实现：恒返回 None，界面上进程列显示「—」。"""

    def resolve(
        self, local: tuple[str, int], remote: tuple[str, int], proto: int
    ) -> tuple[int, str] | None:
        return None
