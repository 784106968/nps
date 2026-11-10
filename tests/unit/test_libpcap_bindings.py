"""绑定层结构体与常量校验（不加载动态库，可在无 Npcap 的 CI 运行）。"""

from __future__ import annotations

import ctypes

from nps.capture import libpcap


def test_timeval_matches_c_long_width() -> None:
    # Windows 上 time_t 是 32 位 long，Linux x86_64 是 64 位；必须跟随平台
    assert ctypes.sizeof(libpcap.Timeval) == 2 * ctypes.sizeof(ctypes.c_long)


def test_pkthdr_field_offsets() -> None:
    assert libpcap.Pkthdr.caplen.offset == 2 * ctypes.sizeof(ctypes.c_long)
    assert libpcap.Pkthdr.len.offset == libpcap.Pkthdr.caplen.offset + 4


def test_pcap_stat_layout() -> None:
    assert ctypes.sizeof(libpcap.PcapStat) == 12
    assert libpcap.PcapStat.ps_drop.offset == 4


def test_bpf_program_layout() -> None:
    assert libpcap.BpfProgram.bf_len.offset == 0
    assert libpcap.BpfProgram.bf_insns.offset == ctypes.sizeof(ctypes.c_void_p)


def test_describe_activate_covers_known_codes() -> None:
    assert libpcap.describe_activate(-8) == "权限不足"
    assert libpcap.describe_activate(-5) == "设备不存在或没有权限"
    assert libpcap.describe_activate(2) == "设备不支持混杂模式"


def test_dlt_names_cover_common_link_types() -> None:
    assert libpcap.DLT_NAMES[libpcap.DLT_EN10MB] == "DLT_EN10MB"
    assert libpcap.DLT_NAMES[libpcap.DLT_LINUX_SLL] == "DLT_LINUX_SLL"


def test_error_type_is_runtime_error() -> None:
    assert issubclass(libpcap.PcapError, RuntimeError)
