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
    echo Downloading the latest installer from GitHub ...
    powershell -NoProfile -ExecutionPolicy Bypass -Command ^
        "[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12;" ^
        "Invoke-WebRequest -UseBasicParsing 'https://raw.githubusercontent.com/robertsonc/netvitals/main/install.ps1' -OutFile (Join-Path $env:TEMP 'netvitals-install.ps1')"
    REM Run via -File so arguments (quotes, spaces) pass through verbatim -
    REM splicing %* inside a -Command string mangles quoted paths.
    if exist "%TEMP%\netvitals-install.ps1" (
        powershell -NoProfile -ExecutionPolicy Bypass -File "%TEMP%\netvitals-install.ps1" %*
    ) else (
        echo ERROR: could not download install.ps1 - check the network/proxy.
        pause
        exit /b 1
    )
)

if errorlevel 1 pause
