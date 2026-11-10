"""分层协议解析。

对外只暴露 ``decode_packet``；每个协议一个模块，返回可挂到详情树上的字段树。
解析结果中的 ``offset/length`` 都是**帧内绝对偏移**，供十六进制视图高亮使用。
"""

from __future__ import annotations

from nps.decode.fields import Decoded, Field
from nps.decode.registry import decode_packet

__all__ = ["Decoded", "Field", "decode_packet"]
