@echo off
chcp 65001 >nul 2>&1
title ASNIPtest - GUI Mode
cd /d "%~dp0"
echo =============================================
echo    ASNIPtest Windows GUI v1.2.0
echo    Cloudflare Node Scanner
echo =============================================
echo.
python asnip_gui.py
if errorlevel 1 (
    echo.
    echo ERROR: Failed to start GUI
    echo.
    pause
)