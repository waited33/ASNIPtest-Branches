@echo off
chcp 65001 >nul
cd /d "%~dp0"

echo ========================================
echo   ASNIPtest Windows 版 安装/配置
echo ========================================
echo.

echo [1/4] 检查 Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到 Python，请先安装 Python 3.8+
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)
python --version
echo.

echo [2/4] 检查 masscan...
if exist masscan.exe (
    echo [OK] masscan.exe 已存在
) else (
    echo [警告] masscan.exe 未找到
    echo 请从以下地址下载 Windows 版:
    echo https://github.com/robertdavidgraham/masscan/releases
    echo 下载后将 masscan.exe 放到项目目录
)
echo.

echo [3/4] 检查 cf-scanner...
if exist cf-scanner.exe (
    echo [OK] cf-scanner.exe 已存在
) else (
    echo [警告] cf-scanner.exe 未找到
    echo 请从项目 Release 页面下载或自行编译
)
echo.

echo [4/4] 安装 Python 依赖...
pip install urllib3 >nul 2>&1
echo [OK] Python 依赖检查完成
echo.

echo ========================================
echo   安装完成！
echo ========================================
echo.
echo 使用方法:
echo   - 图形界面: 双击 start_gui.bat
echo   - 命令行:   run.bat AS209242
echo.
pause
