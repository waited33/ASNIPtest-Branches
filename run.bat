@echo off
cd /d "%~dp0"
if "%~1"=="" (
    echo 用法: run.bat AS209242 或 run.bat AS209242,AS3214
    pause
    exit /b 1
)
python run_win.py %*
