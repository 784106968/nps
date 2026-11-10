"""GUI 入口的可用性与降级行为（不需要安装 PySide6）。"""

from __future__ import annotations

import sys

from nps.gui import run_gui


def test_missing_pyside_returns_hint(monkeypatch, capsys) -> None:
    # 把子模块置为 None，import 时会抛 ImportError，模拟未安装 GUI 依赖
    monkeypatch.setitem(sys.modules, "PySide6.QtWidgets", None)

    assert run_gui([]) == 1
    err = capsys.readouterr().err
    assert "PySide6" in err
    assert ".[gui]" in err
