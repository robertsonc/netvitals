#Requires -Version 5.0
<#
.SYNOPSIS
  Network Vitals installer for Windows - no admin rights required.

.DESCRIPTION
  Installs Network Vitals for the current user:
    * finds Python 3.8+ (with Tkinter); if none, downloads the official
      python.org installer and installs it per-user (silently),
    * copies the app to the install folder (from this folder when run out of
      a repo checkout / release download, otherwise straight from GitHub),
    * creates Start Menu / Desktop shortcuts that open the graphical
      launcher (pythonw.exe, so no console window),
    * registers in Settings > Apps ("Add/Remove Programs") with an
      uninstaller, so Network Vitals shows up like a normal Windows app.

  Run it by double-clicking install.bat, or directly:
    powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1

.PARAMETER InstallDir
  Where to install (default: %LOCALAPPDATA%\Programs\NetVitals).
.PARAMETER NoGui
  Use console output instead of the setup window.
.PARAMETER Silent
  No window, no prompts - install with the given options (implies -NoGui).
.PARAMETER NoDesktopShortcut
  Skip the desktop shortcut.
.PARAMETER NoStartMenuShortcut
  Skip the Start Menu shortcut.
.PARAMETER SkipPythonInstall
  Never install Python; fail instead if a usable one isn't found.
.PARAMETER Branch
  Git branch to fetch when downloading from GitHub (default: main).
#>
[CmdletBinding()]
param(
    [string]$InstallDir = "$env:LOCALAPPDATA\Programs\NetVitals",
    [switch]$NoGui,
    [switch]$Silent,
    [switch]$NoDesktopShortcut,
    [switch]$NoStartMenuShortcut,
    [switch]$SkipPythonInstall,
    [string]$Branch = "main"
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

$AppName       = "Network Vitals"
$AppKey        = "NetVitals"   # registry key + folder name
$Repo          = "robertsonc/netvitals"
$RepoUrl       = "https://github.com/$Repo"
$PythonVersion = "3.12.10"     # installed only when no usable Python exists
$AppFiles      = @("netquality.py", "run.bat", "update.bat", "build_exe.bat",
                   "install.ps1", "uninstall.ps1", "install.bat",
                   "README.md", "requirements.txt")

if ($Silent) { $NoGui = $true }

# PS 5.1 defaults to TLS 1.0 - python.org and GitHub require TLS 1.2+.
try {
    [Net.ServicePointManager]::SecurityProtocol =
        [Net.ServicePointManager]::SecurityProtocol -bor
        [Net.SecurityProtocolType]::Tls12
} catch {}

# ---------------------------------------------------------------------------
# Logging - console by default; the GUI redirects this into its log box.
# ---------------------------------------------------------------------------
$script:GuiLogBox = $null
function Write-Log {
    param([string]$Message)
    if ($script:GuiLogBox -ne $null) {
        $script:GuiLogBox.AppendText($Message + [Environment]::NewLine)
        [System.Windows.Forms.Application]::DoEvents()
    } else {
        Write-Host $Message
    }
}

# ---------------------------------------------------------------------------
# Python discovery / install
# ---------------------------------------------------------------------------
function Test-PythonExe {
    # Probe one candidate interpreter. Returns $null or an object with
    # Exe / Version / HasTk. A temp probe file sidesteps every PowerShell
    # argument-quoting pitfall, and real execution filters out the
    # Microsoft Store stub (which exits non-zero when given arguments).
    param([string]$Command, [string[]]$PreArgs = @())
    $probe = Join-Path $env:TEMP "nv-pyprobe.py"
    Set-Content -Path $probe -Encoding ASCII -Value @(
        "import sys, importlib.util",
        "print('%d.%d' % sys.version_info[:2])",
        "print(sys.executable)",
        "print(1 if importlib.util.find_spec('_tkinter') else 0)"
    )
    try {
        $out = & $Command @PreArgs $probe 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $out) { return $null }
        $lines = @($out | ForEach-Object { "$_".Trim() } | Where-Object { $_ })
        if ($lines.Count -lt 3) { return $null }
        $ver = $null
        if (-not [Version]::TryParse($lines[0], [ref]$ver)) { return $null }
        return [pscustomobject]@{
            Exe     = $lines[1]
            Version = $ver
            HasTk   = ($lines[2] -eq "1")
        }
    } catch {
        return $null
    } finally {
        Remove-Item $probe -ErrorAction SilentlyContinue
    }
}

function Find-Python {
    # Try the py launcher, then PATH names, then the default per-user and
    # per-machine install folders (a just-installed Python isn't on THIS
    # process's PATH yet - the environment was read at startup).
    $tries = @()
    if (Get-Command py -ErrorAction SilentlyContinue) {
        $tries += ,@("py", @("-3"))
    }
    foreach ($name in @("python", "python3")) {
        if (Get-Command $name -ErrorAction SilentlyContinue) {
            $tries += ,@($name, @())
        }
    }
    foreach ($root in @("$env:LOCALAPPDATA\Programs\Python",
                        $env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if (-not $root) { continue }
        foreach ($exe in (Get-ChildItem -Path "$root\Python3*\python.exe" `
                          -ErrorAction SilentlyContinue |
                          Sort-Object FullName -Descending)) {
            $tries += ,@($exe.FullName, @())
        }
    }
    $best = $null
    foreach ($t in $tries) {
        $found = Test-PythonExe -Command $t[0] -PreArgs $t[1]
        if (-not $found) { continue }
        if ($found.Version -lt [Version]"3.8") { continue }
        if ($found.HasTk) { return $found }        # ideal: take it
        if (-not $best) { $best = $found }         # remember a tk-less one
    }
    return $best  # may be $null, or a Python without Tkinter
}

function Get-RemoteFile {
    # Async download + message pump so the GUI stays responsive.
    param([string]$Url, [string]$Destination, [string]$What)
    Write-Log "Downloading $What ..."
    Write-Log "  $Url"
    $wc = New-Object System.Net.WebClient
    $wc.Headers.Add("User-Agent", "netvitals-installer")
    try {
        $task = $wc.DownloadFileTaskAsync($Url, $Destination)
        while (-not $task.IsCompleted) {
            Start-Sleep -Milliseconds 100
            if ($script:GuiLogBox -ne $null) {
                [System.Windows.Forms.Application]::DoEvents()
            }
        }
        if ($task.IsFaulted) { throw $task.Exception.InnerException }
    } finally {
        $wc.Dispose()
    }
    $mb = [math]::Round((Get-Item $Destination).Length / 1MB, 1)
    Write-Log "  done ($mb MB)."
}

function Install-Python {
    # Silent per-user install from python.org: no admin, includes Tkinter,
    # pip and the py launcher, and adds Python to the user PATH.
    $suffix = switch ($env:PROCESSOR_ARCHITECTURE) {
        "ARM64" { "-arm64" }
        "AMD64" { "-amd64" }
        default { "" }       # 32-bit x86
    }
    $url = "https://www.python.org/ftp/python/$PythonVersion/python-$PythonVersion$suffix.exe"
    $tmp = Join-Path $env:TEMP "python-$PythonVersion-setup.exe"
    Get-RemoteFile -Url $url -Destination $tmp -What "Python $PythonVersion"
    Write-Log "Installing Python $PythonVersion (current user, this takes a minute or two) ..."
    $arguments = @("/quiet", "InstallAllUsers=0", "InstallLauncherAllUsers=0",
                   "PrependPath=1", "Include_tcltk=1", "Include_pip=1",
                   "Include_test=0", "AssociateFiles=0")
    $proc = Start-Process -FilePath $tmp -ArgumentList $arguments -PassThru
    while (-not $proc.HasExited) {
        Start-Sleep -Milliseconds 250
        if ($script:GuiLogBox -ne $null) {
            [System.Windows.Forms.Application]::DoEvents()
        }
    }
    Remove-Item $tmp -ErrorAction SilentlyContinue
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        throw "Python installer failed (exit code $($proc.ExitCode))."
    }
    $py = Find-Python
    if (-not $py) { throw "Python was installed but can't be located - open a NEW terminal and re-run the installer." }
    if (-not $py.HasTk) { throw "Python was installed but Tkinter is missing - re-run the python.org installer and enable 'tcl/tk and IDLE'." }
    Write-Log "Installed Python $($py.Version) -> $($py.Exe)"
    return $py
}

function Resolve-Python {
    $py = Find-Python
    if ($py -and $py.HasTk) {
        Write-Log "Found Python $($py.Version) with Tkinter -> $($py.Exe)"
        return $py
    }
    if ($py -and -not $py.HasTk) {
        Write-Log "Found Python $($py.Version) at $($py.Exe), but WITHOUT Tkinter (the GUI toolkit)."
        if ($SkipPythonInstall) {
            throw "Python lacks Tkinter and -SkipPythonInstall was given. Re-run the python.org installer and enable 'tcl/tk and IDLE'."
        }
        Write-Log "Installing a separate per-user Python $PythonVersion that includes it ..."
        return Install-Python
    }
    if ($SkipPythonInstall) {
        throw "No Python 3.8+ found and -SkipPythonInstall was given."
    }
    Write-Log "No usable Python found - installing Python $PythonVersion for the current user."
    return Install-Python
}

# ---------------------------------------------------------------------------
# App files
# ---------------------------------------------------------------------------
function Get-SourceDir {
    # A repo checkout / release download has netquality.py next to this
    # script - install offline from there. Otherwise fetch the branch zip.
    if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "netquality.py"))) {
        Write-Log "Installing from local folder: $PSScriptRoot"
        return $PSScriptRoot
    }
    $zip = Join-Path $env:TEMP "netvitals-$Branch.zip"
    $dst = Join-Path $env:TEMP "netvitals-unzip"
    Get-RemoteFile -Url "https://codeload.github.com/$Repo/zip/refs/heads/$Branch" `
                   -Destination $zip -What "$AppName ($Branch branch)"
    if (Test-Path $dst) { Remove-Item $dst -Recurse -Force }
    Expand-Archive -Path $zip -DestinationPath $dst -Force
    Remove-Item $zip -ErrorAction SilentlyContinue
    $inner = Get-ChildItem -Path $dst -Directory | Select-Object -First 1
    if (-not $inner -or -not (Test-Path (Join-Path $inner.FullName "netquality.py"))) {
        throw "Downloaded archive doesn't contain netquality.py - wrong branch?"
    }
    return $inner.FullName
}

function Get-AppVersion {
    param([string]$Dir)
    $m = Select-String -Path (Join-Path $Dir "netquality.py") `
                       -Pattern '^__version__\s*=\s*"([^"]+)"' |
         Select-Object -First 1
    if ($m) { return $m.Matches[0].Groups[1].Value }
    return "0.0.0"
}

function Install-AppFiles {
    param([string]$SourceDir)
    Write-Log "Copying application files to $InstallDir ..."
    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    foreach ($f in $AppFiles) {
        $src = Join-Path $SourceDir $f
        if (Test-Path $src) {
            Copy-Item $src -Destination $InstallDir -Force
        }
    }
    $assets = Join-Path $SourceDir "assets"
    if (Test-Path $assets) {
        Copy-Item $assets -Destination $InstallDir -Recurse -Force
    }
}

# ---------------------------------------------------------------------------
# Shortcuts + Add/Remove Programs registration
# ---------------------------------------------------------------------------
function New-AppShortcut {
    param([string]$LinkPath, [string]$PythonwExe)
    $shell = New-Object -ComObject WScript.Shell
    $lnk = $shell.CreateShortcut($LinkPath)
    $lnk.TargetPath = $PythonwExe
    $lnk.Arguments = "`"$InstallDir\netquality.py`""
    $lnk.WorkingDirectory = $InstallDir
    $lnk.Description = "$AppName - network loss / latency / jitter dashboard"
    $ico = Join-Path $InstallDir "assets\netvitals.ico"
    if (Test-Path $ico) { $lnk.IconLocation = "$ico,0" }
    $lnk.Save()
    Write-Log "Shortcut: $LinkPath"
}

function Install-Shortcuts {
    param($Python)
    # pythonw.exe runs the GUI with no console window; the launcher opens.
    $pythonw = Join-Path (Split-Path $Python.Exe) "pythonw.exe"
    if (-not (Test-Path $pythonw)) { $pythonw = $Python.Exe }
    if (-not $NoStartMenuShortcut) {
        $programs = Join-Path $env:APPDATA "Microsoft\Windows\Start Menu\Programs"
        New-AppShortcut -LinkPath (Join-Path $programs "$AppName.lnk") -PythonwExe $pythonw
    }
    if (-not $NoDesktopShortcut) {
        $desktop = [Environment]::GetFolderPath("Desktop")
        New-AppShortcut -LinkPath (Join-Path $desktop "$AppName.lnk") -PythonwExe $pythonw
    }
}

function Register-App {
    param([string]$Version)
    $reg = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\$AppKey"
    New-Item -Path $reg -Force | Out-Null
    $ps = "$env:WINDIR\System32\WindowsPowerShell\v1.0\powershell.exe"
    $uninst = "`"$ps`" -NoProfile -ExecutionPolicy Bypass -File `"$InstallDir\uninstall.ps1`""
    $sizeKB = [int]((Get-ChildItem -Path $InstallDir -Recurse -File |
                     Measure-Object -Property Length -Sum).Sum / 1KB)
    Set-ItemProperty -Path $reg -Name "DisplayName" -Value $AppName
    Set-ItemProperty -Path $reg -Name "DisplayVersion" -Value $Version
    Set-ItemProperty -Path $reg -Name "Publisher" -Value $AppName
    Set-ItemProperty -Path $reg -Name "InstallLocation" -Value $InstallDir
    Set-ItemProperty -Path $reg -Name "DisplayIcon" -Value "$InstallDir\assets\netvitals.ico"
    Set-ItemProperty -Path $reg -Name "UninstallString" -Value $uninst
    Set-ItemProperty -Path $reg -Name "QuietUninstallString" -Value "$uninst -Silent"
    Set-ItemProperty -Path $reg -Name "URLInfoAbout" -Value $RepoUrl
    Set-ItemProperty -Path $reg -Name "HelpLink" -Value $RepoUrl
    Set-ItemProperty -Path $reg -Name "InstallDate" -Value (Get-Date -Format "yyyyMMdd")
    Set-ItemProperty -Path $reg -Name "NoModify" -Value 1 -Type DWord
    Set-ItemProperty -Path $reg -Name "NoRepair" -Value 1 -Type DWord
    Set-ItemProperty -Path $reg -Name "EstimatedSize" -Value $sizeKB -Type DWord
    Write-Log "Registered in Settings > Apps (uninstall from there any time)."
}

# ---------------------------------------------------------------------------
# The install itself (shared by GUI and console modes)
# ---------------------------------------------------------------------------
function Invoke-Install {
    Write-Log "=== $AppName setup ==="
    $py = Resolve-Python
    $srcDir = Get-SourceDir
    $version = Get-AppVersion -Dir $srcDir
    Write-Log "Installing $AppName $version ..."
    Install-AppFiles -SourceDir $srcDir
    Install-Shortcuts -Python $py
    Register-App -Version $version
    Write-Log ""
    Write-Log "$AppName $version installed to:"
    Write-Log "  $InstallDir"
    Write-Log "Start it from the Start Menu ('$AppName') - the launch window"
    Write-Log "opens, where the peer IP and every option can be set."
    return [pscustomobject]@{
        Python  = $py
        Version = $version
    }
}

function Start-App {
    param($Python)
    $pythonw = Join-Path (Split-Path $Python.Exe) "pythonw.exe"
    if (-not (Test-Path $pythonw)) { $pythonw = $Python.Exe }
    Start-Process -FilePath $pythonw -ArgumentList "`"$InstallDir\netquality.py`"" `
                  -WorkingDirectory $InstallDir
}

# ---------------------------------------------------------------------------
# WinForms setup window (default). Falls back to console when unavailable.
# ---------------------------------------------------------------------------
function Show-InstallerGui {
    Add-Type -AssemblyName System.Windows.Forms
    Add-Type -AssemblyName System.Drawing

    $bg     = [System.Drawing.Color]::FromArgb(26, 29, 33)
    $panel  = [System.Drawing.Color]::FromArgb(35, 39, 46)
    $txtCol = [System.Drawing.Color]::FromArgb(242, 244, 245)
    $dimCol = [System.Drawing.Color]::FromArgb(154, 163, 173)
    $green  = [System.Drawing.Color]::FromArgb(1, 169, 130)

    $form = New-Object System.Windows.Forms.Form
    $form.Text = "$AppName setup"
    $form.ClientSize = New-Object System.Drawing.Size(560, 470)
    $form.BackColor = $bg
    $form.FormBorderStyle = "FixedSingle"
    $form.MaximizeBox = $false
    $form.StartPosition = "CenterScreen"

    $title = New-Object System.Windows.Forms.Label
    $title.Text = "$AppName setup"
    $title.Font = New-Object System.Drawing.Font("Segoe UI", 16, [System.Drawing.FontStyle]::Bold)
    $title.ForeColor = $txtCol
    $title.AutoSize = $true
    $title.Location = New-Object System.Drawing.Point(20, 16)
    $form.Controls.Add($title)

    $sub = New-Object System.Windows.Forms.Label
    $sub.Text = "Measures loss, latency and jitter between two workstations."
    $sub.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $sub.ForeColor = $dimCol
    $sub.AutoSize = $true
    $sub.Location = New-Object System.Drawing.Point(22, 48)
    $form.Controls.Add($sub)

    $pyLabel = New-Object System.Windows.Forms.Label
    $pyLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $pyLabel.AutoSize = $true
    $pyLabel.Location = New-Object System.Drawing.Point(22, 74)
    $pyProbe = Find-Python
    if ($pyProbe -and $pyProbe.HasTk) {
        $pyLabel.Text = "Python $($pyProbe.Version) with Tkinter found - nothing extra to install."
        $pyLabel.ForeColor = $green
    } elseif ($pyProbe) {
        $pyLabel.Text = "Python $($pyProbe.Version) found but without Tkinter - Python $PythonVersion will be added (per-user, python.org)."
        $pyLabel.ForeColor = $dimCol
    } else {
        $pyLabel.Text = "Python not found - Python $PythonVersion will be installed for you (per-user, from python.org)."
        $pyLabel.ForeColor = $dimCol
    }
    $form.Controls.Add($pyLabel)

    $dirLabel = New-Object System.Windows.Forms.Label
    $dirLabel.Text = "Install folder:"
    $dirLabel.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $dirLabel.ForeColor = $txtCol
    $dirLabel.AutoSize = $true
    $dirLabel.Location = New-Object System.Drawing.Point(22, 104)
    $form.Controls.Add($dirLabel)

    $dirBox = New-Object System.Windows.Forms.TextBox
    $dirBox.Text = $InstallDir
    $dirBox.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $dirBox.BackColor = $panel
    $dirBox.ForeColor = $txtCol
    $dirBox.BorderStyle = "FixedSingle"
    $dirBox.Location = New-Object System.Drawing.Point(24, 124)
    $dirBox.Size = New-Object System.Drawing.Size(430, 24)
    $form.Controls.Add($dirBox)

    $browse = New-Object System.Windows.Forms.Button
    $browse.Text = "Browse..."
    $browse.FlatStyle = "Flat"
    $browse.BackColor = $panel
    $browse.ForeColor = $txtCol
    $browse.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(54, 59, 68)
    $browse.Location = New-Object System.Drawing.Point(462, 123)
    $browse.Size = New-Object System.Drawing.Size(78, 25)
    $browse.Add_Click({
        $dlg = New-Object System.Windows.Forms.FolderBrowserDialog
        $dlg.Description = "Choose the parent folder ('$AppKey' is created inside it)"
        if ($dlg.ShowDialog() -eq "OK") {
            $dirBox.Text = Join-Path $dlg.SelectedPath $AppKey
        }
    })
    $form.Controls.Add($browse)

    $cbStart = New-Object System.Windows.Forms.CheckBox
    $cbStart.Text = "Start Menu shortcut"
    $cbStart.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $cbStart.ForeColor = $txtCol
    $cbStart.Checked = -not $NoStartMenuShortcut
    $cbStart.AutoSize = $true
    $cbStart.Location = New-Object System.Drawing.Point(24, 158)
    $form.Controls.Add($cbStart)

    $cbDesk = New-Object System.Windows.Forms.CheckBox
    $cbDesk.Text = "Desktop shortcut"
    $cbDesk.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $cbDesk.ForeColor = $txtCol
    $cbDesk.Checked = -not $NoDesktopShortcut
    $cbDesk.AutoSize = $true
    $cbDesk.Location = New-Object System.Drawing.Point(200, 158)
    $form.Controls.Add($cbDesk)

    $log = New-Object System.Windows.Forms.TextBox
    $log.Multiline = $true
    $log.ReadOnly = $true
    $log.ScrollBars = "Vertical"
    $log.Font = New-Object System.Drawing.Font("Consolas", 8.5)
    $log.BackColor = $panel
    $log.ForeColor = $txtCol
    $log.BorderStyle = "FixedSingle"
    $log.Location = New-Object System.Drawing.Point(24, 190)
    $log.Size = New-Object System.Drawing.Size(516, 200)
    $form.Controls.Add($log)

    $bar = New-Object System.Windows.Forms.ProgressBar
    $bar.Style = "Continuous"
    $bar.Location = New-Object System.Drawing.Point(24, 398)
    $bar.Size = New-Object System.Drawing.Size(516, 6)
    $form.Controls.Add($bar)

    $btnInstall = New-Object System.Windows.Forms.Button
    $btnInstall.Text = "Install"
    $btnInstall.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnInstall.FlatStyle = "Flat"
    $btnInstall.BackColor = $green
    $btnInstall.ForeColor = [System.Drawing.Color]::White
    $btnInstall.FlatAppearance.BorderSize = 0
    $btnInstall.Location = New-Object System.Drawing.Point(430, 418)
    $btnInstall.Size = New-Object System.Drawing.Size(110, 36)
    $form.Controls.Add($btnInstall)

    $btnLaunch = New-Object System.Windows.Forms.Button
    $btnLaunch.Text = "Launch"
    $btnLaunch.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $btnLaunch.FlatStyle = "Flat"
    $btnLaunch.BackColor = $green
    $btnLaunch.ForeColor = [System.Drawing.Color]::White
    $btnLaunch.FlatAppearance.BorderSize = 0
    $btnLaunch.Location = New-Object System.Drawing.Point(430, 418)
    $btnLaunch.Size = New-Object System.Drawing.Size(110, 36)
    $btnLaunch.Visible = $false
    $form.Controls.Add($btnLaunch)

    $btnClose = New-Object System.Windows.Forms.Button
    $btnClose.Text = "Close"
    $btnClose.Font = New-Object System.Drawing.Font("Segoe UI", 9)
    $btnClose.FlatStyle = "Flat"
    $btnClose.BackColor = $panel
    $btnClose.ForeColor = $txtCol
    $btnClose.FlatAppearance.BorderColor = [System.Drawing.Color]::FromArgb(54, 59, 68)
    $btnClose.Location = New-Object System.Drawing.Point(330, 418)
    $btnClose.Size = New-Object System.Drawing.Size(90, 36)
    $btnClose.Add_Click({ $form.Close() })
    $form.Controls.Add($btnClose)

    $result = @{ Python = $null }
    $btnInstall.Add_Click({
        $btnInstall.Enabled = $false
        $browse.Enabled = $false
        $dirBox.Enabled = $false
        $script:InstallDir = $dirBox.Text.Trim()
        $script:NoStartMenuShortcut = -not $cbStart.Checked
        $script:NoDesktopShortcut = -not $cbDesk.Checked
        $script:GuiLogBox = $log
        $bar.Style = "Marquee"
        try {
            $r = Invoke-Install
            $result.Python = $r.Python
            $bar.Style = "Continuous"
            $bar.Value = 100
            $btnInstall.Visible = $false
            $btnLaunch.Visible = $true
        } catch {
            $bar.Style = "Continuous"
            $bar.Value = 0
            Write-Log ""
            Write-Log "INSTALL FAILED: $($_.Exception.Message)"
            [System.Windows.Forms.MessageBox]::Show(
                $_.Exception.Message, "$AppName setup",
                [System.Windows.Forms.MessageBoxButtons]::OK,
                [System.Windows.Forms.MessageBoxIcon]::Error) | Out-Null
            $btnInstall.Enabled = $true
            $browse.Enabled = $true
            $dirBox.Enabled = $true
        }
    })
    $btnLaunch.Add_Click({
        Start-App -Python $result.Python
        $form.Close()
    })

    [System.Windows.Forms.Application]::EnableVisualStyles()
    $form.Add_Shown({ $form.Activate() }) | Out-Null
    [void]$form.ShowDialog()
    $form.Dispose()
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
$useGui = -not $NoGui
if ($useGui) {
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        if (-not [Environment]::UserInteractive) { $useGui = $false }
    } catch {
        $useGui = $false
    }
}

if ($useGui) {
    Show-InstallerGui
} else {
    if (-not $Silent) {
        Write-Host "=== $AppName setup (console) ==="
        Write-Host "Install folder : $InstallDir"
        Write-Host "Shortcuts      : StartMenu=$(-not $NoStartMenuShortcut)  Desktop=$(-not $NoDesktopShortcut)"
        $answer = Read-Host "Proceed? [Y/n]"
        if ($answer -and $answer.Trim().ToLower().StartsWith("n")) {
            Write-Host "Cancelled."
            exit 1
        }
    }
    $r = Invoke-Install
    if (-not $Silent) {
        $answer = Read-Host "Launch $AppName now? [Y/n]"
        if (-not ($answer -and $answer.Trim().ToLower().StartsWith("n"))) {
            Start-App -Python $r.Python
        }
    }
}
