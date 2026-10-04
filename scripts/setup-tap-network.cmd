@echo off
setlocal
net session >nul 2>&1
if errorlevel 1 (
  powershell.exe -NoLogo -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b %errorlevel%
)
powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%~dp0setup-tap-network.ps1" %*
if errorlevel 1 pause
exit /b %errorlevel%
