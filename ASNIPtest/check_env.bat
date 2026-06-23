@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"

echo =============================================
echo    ASNIPtest - Environment Check v1.0
echo =============================================
echo.

echo [1/5] Checking Python...
python --version 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found!
) else (
    echo OK: Python is available
)
echo.

echo [2/5] Checking verify.py...
if exist "verify.py" (
    echo OK: verify.py exists
) else (
    echo ERROR: verify.py not found
)
echo.

echo [3/5] Checking cf_hits.txt...
if exist "cf_hits.txt" (
    echo OK: cf_hits.txt exists
    for /f %%a in ('type cf_hits.txt ^| find /c /v ""') do set "count=%%a"
    echo Found %count% IP:port entries
) else (
    echo WARNING: cf_hits.txt not found
)
echo.

echo [4/5] Checking masscan.exe...
if exist "masscan.exe" (
    echo OK: masscan.exe exists
) else (
    echo WARNING: masscan.exe not found
)
echo.

echo [5/5] Testing network...
ping api.090227.xyz -n 1 -w 3000 >nul 2>&1
if %errorlevel% equ 0 (
    echo OK: Can reach API server
) else (
    echo WARNING: Cannot reach API server
)
echo.

echo =============================================
echo Environment check complete!
echo =============================================
echo.
pause