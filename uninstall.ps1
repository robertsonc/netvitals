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

# ---------------------------------------------------------------------------
# Safety: this script deletes ITS OWN folder, so a stray copy in Desktop /
# Downloads / a profile root must never turn into "delete that folder".
# Refuse unless the folder actually looks like a Network Vitals install and
# is not one of the well-known user folders.
# ---------------------------------------------------------------------------
if (-not (Test-Path (Join-Path $InstallDir "netquality.py"))) {
    Write-Host "ERROR: '$InstallDir' does not look like a $AppName install"
    Write-Host "folder (netquality.py is not here). Nothing was removed."
    Write-Host "Uninstall from Settings > Apps, or run the copy of"
    Write-Host "uninstall.ps1 that lives in the install folder."
    exit 1
}
$protected = @([Environment]::GetFolderPath("Desktop"),
               [Environment]::GetFolderPath("MyDocuments"),
               [Environment]::GetFolderPath("UserProfile"),
               $env:USERPROFILE, $env:LOCALAPPDATA, $env:APPDATA,
               $env:TEMP, "$env:SystemDrive\")
foreach ($p in $protected) {
    if ($p -and ($InstallDir.TrimEnd('\') -eq $p.TrimEnd('\'))) {
        Write-Host "ERROR: refusing to remove '$InstallDir' - it is a"
        Write-Host "system/user folder, not an application folder."
        Write-Host "Nothing was removed."
        exit 1
    }
}

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

$running = Get-Process -ErrorAction SilentlyContinue |
           Where-Object { $_.MainWindowTitle -like "$AppName*" }
if ($running) {
    Write-Host "NOTE: $AppName appears to still be running. Close it, or the"
    Write-Host "install folder may survive until the next reboot (its working"
    Write-Host "directory is pinned by the running process)."
}

Write-Host "$AppName has been removed."

# The install folder contains THIS running script, so its deletion is handed
# to a detached cmd that waits for this process to exit and then retries for
# a while (covers a still-closing app releasing the folder).
Set-Location $env:TEMP
$cmd = "/c for /l %i in (1,1,10) do (ping -n 3 127.0.0.1 >nul & " +
       "rmdir /s /q `"$InstallDir`" 2>nul & " +
       "if not exist `"$InstallDir`" exit)"
Start-Process -FilePath "$env:ComSpec" -ArgumentList $cmd -WindowStyle Hidden
