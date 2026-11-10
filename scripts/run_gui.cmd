@echo off
chcp 65001 >nul
setlocal
set "ROOT=%~dp0.."
set "PY=%ROOT%\.venv\Scripts\python.exe"
set "PYW=%ROOT%\.venv\Scripts\pythonw.exe"

if not exist "%PYW%" (
    echo [NPS] 未找到虚拟环境，请先在项目目录执行：
    echo     python -m venv .venv
    echo     .venv\Scripts\python -m pip install -e ".[gui]"
    pause
    exit /b 1
)

"%PY%" -c "import PySide6" >nul 2>nul
if errorlevel 1 (
    echo [NPS] 缺少 PySide6，请执行：
    echo     .venv\Scripts\python -m pip install -e ".[gui]"
    pause
    exit /b 1
)

pushd "%ROOT%"
start "" "%PYW%" -m nps
popd
