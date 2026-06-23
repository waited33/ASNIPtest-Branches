@echo off
chcp 65001 >nul 2>&1
cd /d "%~dp0"

echo =============================================
echo    ASNIPtest Windows CLI v1.2.0
echo =============================================
echo.

if "%~1"=="" (
    echo Usage:
    echo   run.bat AS209242
    echo   run.bat AS209242,AS3214
    echo   run.bat AS209242 AS3214
    echo.
    echo Options:
    echo   --ports 443,8443,2053    Custom ports
    echo   --mode tls               TLS local verification
    echo   --mode api               API remote verification
    echo.
    set /p asn="Enter ASN number: "
) else (
    set asn=%*
)

echo Running: python run_win.py %asn%
echo.

python run_win.py %asn%

echo.
pause