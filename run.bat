@echo off
chcp 65001 >nul
title ASNIPtest - Cloudflare 节点扫描工具

echo ==============================================
echo           ASNIPtest Windows 版本
echo ==============================================
echo 从 ASN 编号出发，自动完成 IP 段拉取 → 端口扫描 → Cloudflare 反代节点检测
echo ==============================================
echo.

:: 检查 Python 是否安装
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ 错误：未找到 Python，请先安装 Python 3.8+
    echo    下载地址：https://www.python.org/downloads/windows/
    pause
    exit /b 1
)

:: 检查 masscan.exe 是否存在
if not exist "masscan.exe" (
    echo ❌ 错误：未找到 masscan.exe
    echo    请从以下地址下载并解压到当前目录：
    echo    https://github.com/robertdavidgraham/masscan/releases
    pause
    exit /b 1
)

:: 检查 cf-scanner.exe 是否存在
if not exist "cf-scanner.exe" (
    echo ❌ 错误：未找到 cf-scanner.exe
    pause
    exit /b 1
)

echo ✅ 环境检查通过
echo.

:: 启动主程序
python run_win.py %*

pause
