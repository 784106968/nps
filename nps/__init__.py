"""NPS — 轻量网络嗅探器（实验 1A）。

捕获层通过 ctypes 直接调用 libpcap / Npcap 的新 API，不依赖第三方绑定。
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
