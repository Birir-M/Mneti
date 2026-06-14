@echo off
:: Mneti Agent - One-Click Installer Launcher
:: Double-click this file. It will request admin rights (UAC prompt),
:: then run setup (location + token) followed by the service installer.

set SCRIPT_DIR=%~dp0

:: Check for admin rights; if not elevated, relaunch elevated
net session >nul 2>&1
if %errorLevel% NEQ 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

cd /d "%SCRIPT_DIR%"
powershell -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT_DIR%Install-Mneti.ps1"
pause