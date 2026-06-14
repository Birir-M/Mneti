#Requires -Version 5.1
<#
.SYNOPSIS
    Mneti Agent - Combined Setup + Install Launcher
.DESCRIPTION
    Runs Setup-Mneti.ps1 (enter building, room, token). On confirmation (Y),
    immediately runs Install-Mneti-Service.ps1 to register the background
    Task Scheduler service. No manual execution-policy or terminal steps needed
    beyond double-clicking Install-Mneti.bat.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ScriptDir   = Split-Path -Parent $MyInvocation.MyCommand.Path
$SetupScript = Join-Path $ScriptDir 'Setup-Mneti.ps1'
$InstallScript = Join-Path $ScriptDir 'Install-MnetiService.ps1'

function Test-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host ''
    Write-Host '  [!] This installer must be run as Administrator.' -ForegroundColor Red
    Write-Host '      Please re-run Install-Mneti.bat and accept the UAC prompt.' -ForegroundColor Yellow
    Write-Host ''
    exit 1
}

if (-not (Test-Path $SetupScript)) {
    Write-Host "  [!] ERROR: Setup-Mneti.ps1 not found in $ScriptDir" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path $InstallScript)) {
    Write-Host "  [!] ERROR: Install-Mneti-Service.ps1 not found in $ScriptDir" -ForegroundColor Red
    exit 1
}

Write-Host ''
Write-Host ('=' * 65) -ForegroundColor Cyan
Write-Host '   Mneti Agent - Full Installation' -ForegroundColor White
Write-Host ('=' * 65) -ForegroundColor Cyan
Write-Host '   Step 1 of 2: Location & token setup'
Write-Host ('=' * 65) -ForegroundColor Cyan
Write-Host ''

# Dot-source Setup-Mneti.ps1 so Invoke-Setup is available in this scope
. $SetupScript

$setupResult = Invoke-Setup

if (-not $setupResult) {
    Write-Host ''
    Write-Host '  [!] Setup was cancelled. Installation aborted.' -ForegroundColor Yellow
    Write-Host ''
    exit 1
}

Write-Host ''
Write-Host ('=' * 65) -ForegroundColor Cyan
Write-Host '   Step 2 of 2: Registering background service' -ForegroundColor White
Write-Host ('=' * 65) -ForegroundColor Cyan
Write-Host ''

& $InstallScript

Write-Host ''
Write-Host ('=' * 65) -ForegroundColor Green
Write-Host '   Installation complete!' -ForegroundColor Green
Write-Host '   The Mneti Agent is now running in the background and will' -ForegroundColor Green
Write-Host '   start automatically every time this PC boots.' -ForegroundColor Green
Write-Host ('=' * 65) -ForegroundColor Green
Write-Host ''