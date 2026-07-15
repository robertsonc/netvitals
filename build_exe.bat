@echo off
REM Build a standalone Windows .exe (requires: pip install pyinstaller)
setlocal
where pyinstaller >nul 2>nul
if errorlevel 1 (
    echo ERROR: pyinstaller not found. Install it first:  pip install pyinstaller
    pause
    exit /b 1
)
set "ICON="
if exist "%~dp0assets\netvitals.ico" set "ICON=--icon "%~dp0assets\netvitals.ico""
pyinstaller --onefile --name netquality %ICON% "%~dp0netquality.py"
if errorlevel 1 (
    echo.
    echo ERROR: build FAILED - do not ship dist\netquality.exe from this run.
    pause
    exit /b 1
)
echo.
echo Built dist\netquality.exe
pause
