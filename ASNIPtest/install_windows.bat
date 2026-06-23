@echo off
chcp 65001 >nul
title ASNIPtest Windows 安装器

echo ==============================================
echo        ASNIPtest Windows 版本安装器
echo ==============================================
echo.

:: 检查是否以管理员身份运行
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ 请以管理员身份运行此脚本
    pause
    exit /b 1
)

echo ✅ 管理员权限确认
echo.

:: 检查 Python
echo 检查 Python 安装...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ⚠️ 未找到 Python，请先安装 Python 3.8+
    echo    下载地址：https://www.python.org/downloads/windows/
    pause
    exit /b 1
)
echo ✅ Python 已安装

:: 检查 masscan
echo.
echo 检查 masscan...
if exist "masscan.exe" (
    echo ✅ masscan.exe 已存在
) else (
    echo ⚠️ 未找到 masscan.exe，尝试自动下载...
    
    :: 尝试从多个源下载
    set "urls[0]=https://github.com/robertdavidgraham/masscan/releases/download/1.3.2/masscan-1.3.2-windows.zip"
    set "urls[1]=https://github.com/robertdavidgraham/masscan/releases/download/1.3.1/masscan-1.3.1-win64.zip"
    
    set "success=0"
    for /l %%i in (0,1,1) do (
        if !success! equ 0 (
            echo 尝试从源 %%i 下载...
            powershell -Command "Invoke-WebRequest -Uri '!urls[%%i]!' -OutFile 'masscan.zip' -UseBasicParsing"
            if %errorlevel% equ 0 (
                echo ✅ 下载成功
                set "success=1"
            )
        )
    )
    
    if !success! equ 0 (
        echo ❌ 自动下载失败，请手动下载：
        echo    https://github.com/robertdavidgraham/masscan/releases
        pause
        exit /b 1
    )
    
    :: 解压
    echo 解压 masscan.zip...
    powershell -Command "Expand-Archive -Path 'masscan.zip' -DestinationPath 'masscan_temp' -Force"
    
    :: 查找 masscan.exe
    for /r "masscan_temp" %%f in (masscan.exe) do (
        copy "%%f" "masscan.exe" >nul
        echo ✅ 已提取 masscan.exe
    )
    
    :: 清理
    rmdir /s /q "masscan_temp"
    del "masscan.zip"
)

:: 检查 cf-scanner
echo.
echo 检查 cf-scanner...
if exist "cf-scanner.exe" (
    echo ✅ cf-scanner.exe 已存在
) else (
    echo ❌ cf-scanner.exe 不存在，请重新克隆项目
    pause
    exit /b 1
)

echo.
echo ==============================================
echo ✅ 安装完成！
echo ==============================================
echo 运行方式：
echo   1. 双击 run.bat（交互模式）
echo   2. 命令行：run.bat AS209242
echo ==============================================
pause
