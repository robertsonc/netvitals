#Requires -Version 5.0
<#
.SYNOPSIS
  Uninstall Network Vitals (per-user install; no admin rights required).

.DESCRIPTION
  Removes the shortcuts, the Settings > Apps registration, and the install
  folder itself. Saved launcher settings (%APPDATA%\NetVitals) are kept
  unless -PurgeSettings is given, so a reinstall picks up where you left off.

.PARAMETER Silent
  No confirmation prompt.
.PARAMETER PurgeSettings
  Also delete the saved launcher settings in %APPDATA%\NetVitals.
#>
[CmdletBinding()]
param(
    [switch]$Silent,
    [switch]$PurgeSettings
)

$ErrorActionPreference = "SilentlyContinue"

$AppName    = "Network Vitals"
$AppKey     = "NetVitals"
$InstallDir = Split-Path -Parent $MyInvocation.MyCommand.Path

if (-not $Silent) {
    Write-Host "This removes $AppName from:"
    Write-Host "  $InstallDir"
    $answer = Read-Host "Continue? [y/N]"
    if (-not ($answer -and $answer.Trim().ToLower().StartsWith("y"))) {
        Write-Host "Cancelled."
        exit 1
    }
}

# Shortcuts
$programs = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
Remove-Item (Join-Path $programs "$AppName.lnk") -Force
Remove-Item (Join-Path ([Environment]::GetFolderPath("Desktop")) "$AppName.lnk") -Force

# Settings > Apps registration
Remove-Item "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppKey" -Recurse -Force

# Saved launcher settings (kept by default so a reinstall remembers the peer)
if ($PurgeSettings) {
    Remove-Item (Join-Path $env:APPDATA $AppKey) -Recurse -Force
}

Write-Host "$AppName has been removed."

# The install folder contains THIS running script, so its deletion is handed
# to a detached cmd that waits a moment for this process to exit first.
Set-Location $env:TEMP
$cmd = "/c ping -n 3 127.0.0.1 >nul & rmdir /s /q `"$InstallDir`""
Start-Process -FilePath "$env:ComSpec" -ArgumentList $cmd -WindowStyle Hidden
