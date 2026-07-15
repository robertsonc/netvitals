@echo off
REM Network Vitals installer bootstrapper. Double-click me.
REM
REM Runs install.ps1 from this folder when present (a repo checkout or
REM release download); otherwise fetches the latest installer straight from
REM GitHub. Any arguments pass through to install.ps1, e.g.:
REM   install.bat -Silent -NoDesktopShortcut
setlocal
title Network Vitals setup

if exist "%~dp0install.ps1" (
    powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1" %*
) else (
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12;" ^
        "$f = Join-Path $env:TEMP 'netvitals-install.ps1';" ^
        "Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/robertsonc/netvitals/main/install.ps1' -OutFile $f;" ^
        "& $f %*"
)

if errorlevel 1 pause
