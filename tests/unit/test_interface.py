"""设备模型与回环识别测试（不加载动态库）。"""

from __future__ import annotations

import pytest

from nps.capture.interface import Interface, choose_default, is_loopback_name
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
    assert "[回环]" in device.label


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
