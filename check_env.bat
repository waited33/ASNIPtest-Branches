@echo off
cd /d "%~dp0"

echo ==============================================
echo      Environment Check Tool
echo ==============================================
echo.

echo [1] Current Directory: %cd%
echo.

echo [2] Checking Python...
python --version 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found
    echo.
) else (
    echo OK: Python is available
)
echo.

echo [3] Checking verify.py...
if exist "verify.py" (
    echo OK: verify.py exists
) else (
    echo ERROR: verify.py not found
)
echo.

echo [4] Checking cf_hits.txt...
if exist "cf_hits.txt" (
    for /f %%a in (cf_hits.txt) do set /a count+=1
    echo OK: cf_hits.txt exists, %count% lines
) else (
    echo WARNING: cf_hits.txt not found
)
echo.

echo [5] Testing network...
ping api.090227.xyz -n 1 -w 3000 >nul 2>&1
if %errorlevel% equ 0 (
    echo OK: Can reach API server
) else (
    echo WARNING: Cannot reach API server
)
echo.

echo ==============================================
echo Press any key to exit...
pause >nul