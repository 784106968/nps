"""GUI 入口。

PySide6 是可选依赖（``pip install -e ".[gui]"``），因此本模块只在真正启动界面时
才导入 Qt，保证核心库与 CI 不被 GUI 依赖绑架。
"""

from __future__ import annotations

import sys


def run_gui(argv: list[str] | None = None) -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print(
            '未安装 PySide6，无法启动图形界面。\n请执行：pip install -e ".[gui]"',
            file=sys.stderr,
        )
        return 1

    from nps.gui.main_window import MainWindow

    app = QApplication.instance() or QApplication(sys.argv[:1] if argv is None else argv)
    window = MainWindow()
    window.show()
    return app.exec()


__all__ = ["run_gui"]
