#Requires -Version 5.1
<#
.SYNOPSIS
    Mneti Agent — Windows Service Installer (Task Scheduler)
.DESCRIPTION
    Configures the Mneti Agent to run silently in the background as a
    persistent Windows system service. Registers a Task Scheduler task
    that triggers on system startup and runs as the NT AUTHORITY\SYSTEM account
    with highest privileges.
.NOTES
    Must be run as Administrator.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TASK_NAME   = "MnetiAgent"
$AGENT_DIR   = "C:\ProgramData\Locator"
$AGENT_FILE  = "start-Mneti.ps1"
$TARGET_PATH = Join-Path $AGENT_DIR $AGENT_FILE

function Write-Banner {
    Write-Host ''
    Write-Host ('=' * 65) -ForegroundColor Cyan
    Write-Host '   Mneti Agent — Service Installer' -ForegroundColor White
    Write-Host ('=' * 65) -ForegroundColor Cyan
    Write-Host '   This script registers the background UDP listener agent'
    Write-Host '   to run silently as a startup system task.'
    Write-Host ('=' * 65) -ForegroundColor Cyan
    Write-Host ''
}

function Test-Admin {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ── Main ──────────────────────────────────────────────────────────────────────
Write-Banner

if (-not (Test-Admin)) {
    Write-Host "  [!] ERROR: This script must be run as Administrator." -ForegroundColor Red
    Write-Host "      Right-click PowerShell -> Run as Administrator" -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# 1. Create Target Directory and Copy Agent Script
if (-not (Test-Path $AGENT_DIR)) {
    New-Item -ItemType Directory -Path $AGENT_DIR -Force | Out-Null
    Write-Host "  [+] Created directory: $AGENT_DIR" -ForegroundColor Green
}

# Copy the agent script to ProgramData
$sourcePath = Join-Path $PSScriptRoot $AGENT_FILE
if (Test-Path $sourcePath) {
    Copy-Item -Path $sourcePath -Destination $TARGET_PATH -Force
    Write-Host "  [+] Copied agent script to $TARGET_PATH" -ForegroundColor Green
} else {
    Write-Host "  [!] WARNING: Source agent script not found in $PSScriptRoot." -ForegroundColor Yellow
    Write-Host "      Will assume it is already at $TARGET_PATH." -ForegroundColor Yellow
}

# 2. Check if setup was already run
$configFile = Join-Path $AGENT_DIR "config.json"
if (-not (Test-Path $configFile)) {
    Write-Host "  [!] WARNING: C:\ProgramData\Locator\config.json is missing!" -ForegroundColor Yellow
    Write-Host "      Please run Setup-Mneti.ps1 first to enter location details." -ForegroundColor Yellow
    Write-Host ""
}

# 3. Create or Update Task Scheduler Task
Write-Host "  [*] Registering startup task in Windows Task Scheduler..." -ForegroundColor Cyan

# Define task actions and triggers
$psPath = "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe"
# Run with -NoLogo, -NoProfile, -WindowStyle Hidden, and execution bypass
$arguments = "-NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$TARGET_PATH`""

# Check if task already exists, remove if it does to perform a clean update
if (Get-ScheduledTask -TaskName $TASK_NAME -ErrorAction SilentlyContinue) {
    Unregister-ScheduledTask -TaskName $TASK_NAME -Confirm:$false | Out-Null
    Write-Host "  [-] Unregistered existing scheduled task." -ForegroundColor DarkYellow
}

# Construct task settings using native CIM cmdlets (available in PS 5.1+)
try {
    $action = New-ScheduledTaskAction -Execute $psPath -Argument $arguments
    $trigger = New-ScheduledTaskTrigger -AtStartup
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # Configure task settings (ensure it runs on battery, doesn't stop after 3 days, restarts on failure)
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Days 365)
    
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    
    # Register the task
    Register-ScheduledTask -TaskName $TASK_NAME -InputObject $task | Out-Null
    
    Write-Host "  [+] Startup Task '$TASK_NAME' successfully registered." -ForegroundColor Green
    Write-Host "      Runs as: NT AUTHORITY\SYSTEM (Silently in background)" -ForegroundColor DarkGreen
} catch {
    Write-Host "  [!] ERROR: Failed to register Task Scheduler task: $_" -ForegroundColor Red
    Write-Host "      Ensure Task Scheduler service is running." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# 4. Configure Windows Firewall Rules
Write-Host "  [*] Configuring Windows Firewall rules for Mneti Agent..." -ForegroundColor Cyan
try {
    # Check if NetSecurity module is available (Windows 8 / Windows Server 2012+)
    if (Get-Module -ListAvailable -Name NetSecurity) {
        # Allow UDP 5000 (Discovery packets)
        if (-not (Get-NetFirewallRule -Name "Mneti_UDP_5000" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name "Mneti_UDP_5000" -DisplayName "Mneti Agent Discovery (UDP 5000)" `
                                -Description "Allows incoming UDP discovery packets from the Mneti Server." `
                                -Direction Inbound -Protocol UDP -LocalPort 5000 -Action Allow -Enabled True | Out-Null
            Write-Host "  [+] Added firewall rule for UDP port 5000." -ForegroundColor Green
        } else {
            Write-Host "  [.] Firewall rule for UDP port 5000 already exists." -ForegroundColor Gray
        }

        # Allow TCP 5002-5005 (Relay callbacks)
        if (-not (Get-NetFirewallRule -Name "Mneti_TCP_Relay" -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -Name "Mneti_TCP_Relay" -DisplayName "Mneti Agent Relay Callback (TCP 5002-5005)" `
                                -Description "Allows incoming HTTP report forwards from hotspot clients." `
                                -Direction Inbound -Protocol TCP -LocalPort 5002,5003,5004,5005 -Action Allow -Enabled True | Out-Null
            Write-Host "  [+] Added firewall rule for TCP ports 5002-5005." -ForegroundColor Green
        } else {
            Write-Host "  [.] Firewall rule for TCP ports 5002-5005 already exists." -ForegroundColor Gray
        }
    } else {
        # Fallback to legacy netsh commands
        netsh advfirewall firewall show rule name="Mneti Agent Discovery (UDP 5000)" > $null
        if ($LASTEXITCODE -ne 0) {
            netsh advfirewall firewall add rule name="Mneti Agent Discovery (UDP 5000)" `
                dir=in action=allow protocol=UDP localport=5000 enable=yes > $null
            Write-Host "  [+] Added firewall rule for UDP port 5000 via Netsh." -ForegroundColor Green
        }
        
        netsh advfirewall firewall show rule name="Mneti Agent Relay Callback (TCP 5002-5005)" > $null
        if ($LASTEXITCODE -ne 0) {
            netsh advfirewall firewall add rule name="Mneti Agent Relay Callback (TCP 5002-5005)" `
                dir=in action=allow protocol=TCP localport=5002-5005 enable=yes > $null
            Write-Host "  [+] Added firewall rule for TCP ports 5002-5005 via Netsh." -ForegroundColor Green
        }
    }
} catch {
    Write-Host "  [!] WARNING: Failed to configure firewall rules: $_" -ForegroundColor Yellow
    Write-Host "      You may need to manually open UDP port 5000 and TCP port 5002 in Windows Firewall." -ForegroundColor Yellow
}

# 5. Start the Task immediately
Write-Host "  [*] Starting Mneti Agent background task..." -ForegroundColor Cyan
try {
    Start-ScheduledTask -TaskName $TASK_NAME
    Write-Host "  [+] Background task started successfully!" -ForegroundColor Green
    Write-Host "      Logs are written to: $AGENT_DIR\agent.log" -ForegroundColor DarkGreen
} catch {
    Write-Host "  [!] WARNING: Task registered but could not be started immediately: $_" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "  Installation Complete." -ForegroundColor Green
Write-Host "  The Mneti agent will now start automatically whenever this PC boots." -ForegroundColor White
Write-Host ""
exit 0
