@echo off
chcp 65001 >nul
title ASNIPtest GUI

set "SCRIPT_DIR=%~dp0"

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Please install Python 3.8+
    echo Download: https://www.python.org/downloads/windows/
    pause
    exit /b 1
)

echo Starting ASNIPtest GUI...
python "%SCRIPT_DIR%asnip_gui.py"