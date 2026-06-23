@echo off
cd /d "%~dp0"

echo ==============================================
echo      ASNIPtest - Reverify Tool v1.0
echo ==============================================
echo This tool re-verifies scan results using API
echo ==============================================
echo.

echo [1/4] Checking Python...
python --version 2>&1 | findstr /i "Python" >nul
if %errorlevel% neq 0 (
    echo ERROR: Python not found!
    echo Please install Python 3.8+ first
    echo Download: https://www.python.org/downloads/windows/
    echo.
    pause
    exit /b 1
)
echo OK: Python is installed
echo.

echo [2/4] Listing CSV files...
dir /b output_*.csv 2>nul | findstr /v ".txt" > temp_list.txt
if %errorlevel% neq 0 (
    echo WARNING: No output_*.csv files found
) else (
    echo Found CSV files:
    echo ---------------------
    type temp_list.txt
    echo ---------------------
)
del temp_list.txt 2>nul
echo.

:INPUT_LOOP
set "csv_file="
set /p "csv_file=Enter CSV filename (e.g. output_209242_20260622_093944.csv): "

if not defined csv_file (
    echo ERROR: Please enter a filename!
    goto INPUT_LOOP
)

if not exist "%csv_file%" (
    echo ERROR: File not found!
    echo Current directory: %cd%
    echo.
    goto INPUT_LOOP
)

echo.
echo [3/4] Extracting IP:port list...
powershell -Command "Get-Content '%csv_file%' | Select-Object -Skip 1 | ForEach-Object { $_.Split(',')[0] + ':' + $_.Split(',')[1] } | Out-File -FilePath 'to_reverify.txt' -Encoding utf8"

if not exist "to_reverify.txt" (
    echo ERROR: Failed to extract IP list!
    pause
    exit /b 1
)

set /a count=0
for /f %%a in (to_reverify.txt) do set /a count+=1
echo Extracted %count% IP:port entries

echo.
echo [4/4] Running API verification...
echo Please wait, this may take several minutes...
echo.

python verify.py --input to_reverify.txt --output "result_api.csv" --mode api --api "https://api.090227.xyz/check" --concurrent 64

if %errorlevel% neq 0 (
    echo.
    echo WARNING: Errors may have occurred
)

echo.
echo ==============================================
echo Verification complete!
echo ==============================================
echo Input: %csv_file%
echo Output: result_api.csv
echo ==============================================
echo.
echo Press any key to exit...
pause >nul