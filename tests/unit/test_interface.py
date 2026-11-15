"""设备模型与回环识别测试（不加载动态库）。"""

from __future__ import annotations

import pytest

from nps.capture.interface import (
    Interface,
    choose_default,
    decode_device_text,
    default_device_name,
    is_loopback_name,
)
from nps.capture.libpcap import PcapError


@pytest.mark.parametrize(
    "name",
    [
        r"\Device\NPF_Loopback",
        "lo",
        "lo0",
        "loopback",
        "NPF_Loopback",
    ],
)
def test_loopback_names(name: str) -> None:
    assert is_loopback_name(name) is True


@pytest.mark.parametrize(
    "name",
    [r"\Device\NPF_{1234}", "eth0", "Wi-Fi", "en0", "any"],
)
def test_non_loopback_names(name: str) -> None:
    assert is_loopback_name(name) is False


def test_loopback_does_not_support_promisc() -> None:
    device = Interface(name=r"\Device\NPF_Loopback", is_loopback=True)
    assert device.promisc_supported is False


def test_pseudo_device_does_not_support_promisc() -> None:
    device = Interface(name="any")
    assert device.is_pseudo is True
    assert device.promisc_supported is False


def test_label_marks_loopback() -> None:
    device = Interface(name=r"\Device\NPF_Loopback", is_loopback=True)
    assert device.label == "回环抓包（Loopback）"


def test_pseudo_device_label_is_readable() -> None:
    device = Interface(name="any")
    assert device.label == "任意接口（any）"


def test_label_contains_description() -> None:
    device = Interface(name=r"\Device\NPF_{ABC}", description="Intel(R) Wi-Fi")
    assert "Intel(R) Wi-Fi" in device.label


def test_choose_default_prefers_described_physical() -> None:
    devices = [
        Interface(name=r"\Device\NPF_Loopback", is_loopback=True),
        Interface(name="any"),
        Interface(name="eth0", description="Ethernet"),
    ]
    assert choose_default(devices).name == "eth0"


def test_choose_default_falls_back_to_first() -> None:
    devices = [Interface(name=r"\Device\NPF_Loopback", is_loopback=True)]
    assert choose_default(devices).name.endswith("NPF_Loopback")


def test_choose_default_without_devices_raises() -> None:
    with pytest.raises(PcapError):
        choose_default([])


def test_decode_utf8_description() -> None:
    raw = b"Intel(R) Wi-Fi 6 AX201 160MHz"
    assert decode_device_text(raw) == "Intel(R) Wi-Fi 6 AX201 160MHz"


def test_decode_gbk_description() -> None:
    raw = "无线网络适配器".encode("gbk")
    assert decode_device_text(raw) == "无线网络适配器"


def test_decode_utf16_with_bom() -> None:
    raw = "无线网络适配器".encode("utf-16")
    assert decode_device_text(raw) == "无线网络适配器"


def test_decode_strips_control_and_replacement_chars() -> None:
    raw = b"Wi-Fi\x00\x01  Adapter\xef\xbf\xbd"
    assert decode_device_text(raw) == "Wi-Fi Adapter"


def test_decode_garbage_returns_empty() -> None:
    assert decode_device_text(b"\x00\x01\x02\x03") == ""
    assert decode_device_text(b"\xef\xbf\xbd\xef\xbf\xbd") == ""


def test_decode_empty_input() -> None:
    assert decode_device_text(None) == ""
    assert decode_device_text(b"") == ""


def test_label_uses_default_name_when_description_missing() -> None:
    device = Interface(
        name=r"\Device\NPF_{ABC}",
        display_name=default_device_name(2),
    )
    assert device.label == "网络设备 2"
    assert "\ufffd" not in device.label


def test_label_never_exposes_device_path_or_braces() -> None:
    device = Interface(
        name=r"\Device\NPF_{D4BB9266-69A4-4599-AA7F-7194D4900179}",
        description="Intel(R) Wi-Fi 6 AX201 160MHz",
    )
    assert device.label == "Intel(R) Wi-Fi 6 AX201 160MHz"
    assert "\\Device" not in device.label
    assert "{" not in device.label and "}" not in device.label


def test_decode_removes_braced_code_fragments() -> None:
    assert decode_device_text(b"USB Device {ABCD-1234}") == "USB Device"


def test_label_prefers_display_name() -> None:
    device = Interface(name="eth0", description="Ethernet", display_name="网络设备 1")
    assert "网络设备 1" in device.label
    assert "Ethernet" not in device.label
