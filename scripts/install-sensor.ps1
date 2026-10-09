<#
.SYNOPSIS
    Vista Platform Sensor installer for Windows.

.DESCRIPTION
    Windows counterpart to install-sensor.sh. Writes the canonical sensor
    config, installs the sensor as a Windows service that starts on boot and
    restarts on failure, starts it, and waits for the sensor to register itself
    with the control plane.

    Ships alongside crypto-sensor.exe in the sensor release package — run it from
    the directory that contains crypto-sensor.exe.

.EXAMPLE
    .\install-sensor.ps1 -Url https://app.vistasecurity.io -Key REG-xxxx -IP 10.0.0.10 -Name sensor-dc01

.NOTES
    Must be run from an elevated (Administrator) PowerShell session.
#>

[CmdletBinding()]
param(
    # Control plane URL the sensor registers and reports to.
    [string]$Url = "https://app.vistasecurity.io",

    # Registration key minted in the console (REG-...). Required.
    [Parameter(Mandatory = $true)]
    [string]$Key,

    # IP address the operator entered when registering. Required (parity with --ip).
    [Parameter(Mandatory = $true)]
    [string]$IP,

    # Human-readable sensor name. Defaults to the hostname + date.
    [string]$Name = "",

    # Comma-separated capture interfaces. Empty = let the sensor auto-select.
    [string]$Interfaces = "",

    # Deployment profile. Not surfaced in the console; datacenter_host is the
    # full-feature default and matches install-sensor.sh.
    [string]$Profile = "datacenter_host",

    # Install location. The service binPath and -config point here.
    [string]$InstallDir = "$env:ProgramFiles\VistaSensor"
)

$ErrorActionPreference = "Stop"
$ServiceName = "VistaSensor"
$ServiceDisplay = "Vista Platform Crypto Sensor"

function Write-Info  { param($m) Write-Host "[INFO]  $m" -ForegroundColor Green }
function Write-Warn  { param($m) Write-Host "[WARN]  $m" -ForegroundColor Yellow }
function Write-Err   { param($m) Write-Host "[ERROR] $m" -ForegroundColor Red }

# --- Preconditions ---------------------------------------------------------
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Err "This installer must be run from an elevated (Administrator) PowerShell session."
    exit 1
}

$BinarySource = Join-Path $PSScriptRoot "crypto-sensor.exe"
if (-not (Test-Path $BinarySource)) {
    Write-Err "crypto-sensor.exe not found next to this script ($PSScriptRoot)."
    Write-Err "Run install-sensor.ps1 from the extracted sensor package directory."
    exit 1
}

# The version the platform shows is the one stamped into this binary — the
# sensor reports it itself at registration and on every heartbeat.
$SensorVersion = "unknown"
try {
    $versionLine = (& $BinarySource --version 2>$null | Select-Object -First 1)
    if ($versionLine -match ' v(\S+)$') { $SensorVersion = $Matches[1] }
} catch { }

# Packet capture needs Npcap: the sensor loads its wpcap.dll at runtime and
# cannot capture without it. Check before touching the service or config, so a
# missing runtime fails here with instructions rather than as a sensor that
# starts and captures nothing. Npcap installs the DLL under System32\Npcap, and
# also into System32 itself in WinPcap API-compatible mode; the sensor loads
# either.
$wpcapCandidates = @(
    (Join-Path $env:SystemRoot "System32\Npcap\wpcap.dll"),
    (Join-Path $env:SystemRoot "System32\wpcap.dll")
)
if (-not ($wpcapCandidates | Where-Object { Test-Path $_ })) {
    Write-Err "Npcap is not installed; the sensor needs it to capture packets."
    Write-Err "Install it from https://npcap.com/#download (keep 'WinPcap API-compatible Mode' checked), then re-run this installer."
    exit 1
}

if ([string]::IsNullOrWhiteSpace($Name)) {
    $Name = "sensor-$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd')"
}

Write-Host ""
Write-Host "Vista Platform Sensor Installer (Windows)" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Info "Sensor version: $SensorVersion"
Write-Info "Control plane : $Url"
Write-Info "Sensor name   : $Name"
Write-Info "IP address    : $IP"
Write-Info "Profile       : $Profile"
Write-Info "Install dir   : $InstallDir"
Write-Host ""
if ($Profile -ne "datacenter_host") {
    Write-Warn "-Profile $Profile is not applied yet: the sensor registers itself and reports the datacenter_host profile."
}

# --- Layout ----------------------------------------------------------------
$CertsDir  = Join-Path $InstallDir "certs"
$DataDir   = Join-Path $InstallDir "data"
$ConfigPath = Join-Path $InstallDir "sensor-config.yaml"
# The sensor writes its log here when it runs as a service (stderr goes nowhere
# under the Service Control Manager); it rotates at 10 MB to sensor.log.1.
$LogFile    = Join-Path $DataDir "logs\sensor.log"
$uuidPattern = '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$'

# Value of a top-level `key: value` line in the sensor config, quotes removed.
function Get-ConfigValue([string]$key) {
    if (-not (Test-Path $ConfigPath)) { return $null }
    $line = Get-Content $ConfigPath | Where-Object { $_ -match "^${key}:" } | Select-Object -First 1
    if (-not $line) { return $null }
    return ($line -replace "^${key}:\s*", '').Trim().Trim('"', "'")
}

# A host this key already enrolled keeps its identity. Re-running the same
# install command (to upgrade the binary, or by mistake) must not discard the
# certificate and UUID the sensor holds and send it back to register with a key
# it has already spent. A different key means a fresh enrolment.
$keepEnrolment = ((Get-ConfigValue 'sensorId') -match $uuidPattern) -and ((Get-ConfigValue 'registrationKey') -eq $Key)
if ($keepEnrolment) {
    Write-Info "This host is already enrolled with this key (sensor $(Get-ConfigValue 'sensorId')); keeping its identity and configuration."
}

# Stop a previous install so it cannot rewrite the config while we replace it.
if (Get-Service -Name $ServiceName -ErrorAction SilentlyContinue) {
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
}

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null

# Earlier versions of this installer registered on the sensor's behalf and wrote
# a control-plane-generated private key to certs\. That identity was never usable
# by the sensor; do not leave its key on disk. A fresh enrolment also must not
# inherit the previous sensor's certificate.
if (-not $keepEnrolment) {
    foreach ($stale in @($CertsDir, (Join-Path $DataDir "certs"))) {
        if (Test-Path $stale) { Remove-Item -Recurse -Force $stale }
    }
}

Write-Info "Installing sensor binary..."
Copy-Item -Force $BinarySource (Join-Path $InstallDir "crypto-sensor.exe")

# --- Write the canonical sensor config ------------------------------------
# The installer does NOT register the sensor. The sensor registers itself on
# first start: it generates its keypair locally (the private key never leaves
# the host), sends a CSR with its build-stamped version and capabilities, then
# rewrites this file with the UUID the platform accepted and the paths of the
# certificate it was issued. Registering here instead spent the single-use key
# before the sensor could use it and recorded a made-up version.
#
# sensorId carries the sensor NAME until registration: the loader uses a
# non-UUID sensorId as the registration name. Flat camelCase keys — the schema
# sensor/internal/config.ConfigFile parses (nested control_plane:/url: is NOT
# read).
if (-not $keepEnrolment) {
    Write-Info "Writing configuration to $ConfigPath"

    # Single-quoted YAML scalars take backslashes literally; a quote is doubled.
    function ConvertTo-YamlScalar([string]$v) { "'" + $v.Replace("'", "''") + "'" }

    $interfaceList = @()
    if (-not [string]::IsNullOrWhiteSpace($Interfaces)) {
        $interfaceList = $Interfaces.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
    $ifaceYaml = "[" + (($interfaceList | ForEach-Object { ConvertTo-YamlScalar $_ }) -join ", ") + "]"

    $configContent = @"
# Vista Platform Sensor configuration (generated by install-sensor.ps1)
# sensorId holds the sensor's name until it registers, then its UUID.
sensorId: $(ConvertTo-YamlScalar $Name)
controlPlaneUrl: $(ConvertTo-YamlScalar $Url)
registrationKey: $(ConvertTo-YamlScalar $Key)
reportingIntervalSeconds: 30

capture:
  interfaces: $ifaceYaml
  activeProbing: true
  networkDiscovery: true

storage:
  dataPath: $(ConvertTo-YamlScalar $DataDir)
"@
    # UTF-8 without a BOM (Windows PowerShell's Out-File -Encoding utf8 adds one).
    [System.IO.File]::WriteAllText($ConfigPath, $configContent, (New-Object System.Text.UTF8Encoding $false))
}

# --- Install + start the Windows service ----------------------------------
# Auto-start (survives reboot / maintenance) + restart-on-failure = the Windows
# equivalent of systemd `WantedBy=multi-user.target` + `Restart=always`.
Write-Info "Installing Windows service '$ServiceName'..."
$binPath = "`"$InstallDir\crypto-sensor.exe`" --verbose -config `"$ConfigPath`""

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Warn "Service already exists — reconfiguring."
    # sc.exe is the reliable way to rewrite binPath on an existing service.
    sc.exe config $ServiceName binPath= "$binPath" start= auto | Out-Null
} else {
    New-Service -Name $ServiceName -DisplayName $ServiceDisplay `
        -BinaryPathName $binPath -StartupType Automatic `
        -Description "Vista Platform passive crypto-discovery sensor" | Out-Null
}

# Restart on crash: reset failure count daily, restart after 10s on each of the
# first three failures (the SCM repeats the last action for any later one).
sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/10000/restart/10000 | Out-Null
# Also restart when the sensor stops itself with a failure exit code: that is
# how it honours a restart command from the control plane. Without this flag
# the SCM only acts on a crash, and the sensor would stay stopped.
sc.exe failureflag $ServiceName 1 | Out-Null

# The address the operator entered when creating the registration key (-IP).
# Pinning it makes registration report the address the platform expects even on
# a multi-homed host, where the sensor's own guess can differ. Service-scoped
# environment lives in the service's registry key.
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$ServiceName" `
    -Name Environment -Type MultiString -Value @("SENSOR_IP_ADDRESS=$IP")

# Log lines this start wrote: everything past the log's current end. The
# sensor keeps the file open, so share it for writing and for its rotation.
$logStartOffset = 0
if (Test-Path $LogFile) { $logStartOffset = (Get-Item $LogFile).Length }
function Get-NewLogText {
    if (-not (Test-Path $LogFile)) { return "" }
    try {
        $stream = [System.IO.File]::Open($LogFile, 'Open', 'Read', 'ReadWrite, Delete')
        try {
            # A rotation since we started means the whole current file is new.
            if ($stream.Length -ge $logStartOffset) { [void]$stream.Seek($logStartOffset, 'Begin') }
            $reader = New-Object System.IO.StreamReader($stream, [System.Text.Encoding]::UTF8)
            return $reader.ReadToEnd()
        } finally { $stream.Dispose() }
    } catch { return "" }
}

Write-Info "Starting service..."
# The sensor reports Running once it has registered (or begun retrying) and
# started capturing. A sensor that exits during startup (a rejected
# registration key does) makes Start-Service throw; the log says why, so carry
# on to the checks below instead of stopping at the exception.
$startError = $null
try {
    Start-Service -Name $ServiceName
} catch {
    $startError = $_.Exception.Message
}

# --- Wait for the sensor to register itself --------------------------------
# Registration is confirmed only by the sensor: it rewrites sensorId with the
# UUID the platform accepted. A running service is not a registered sensor — an
# unregistered one captures traffic and can submit none of it.
$timeoutSeconds = 90
Write-Info "Waiting up to ${timeoutSeconds}s for the sensor to register..."
$sensorId = $null
$rejected = $false
$deadline = (Get-Date).AddSeconds($timeoutSeconds)
while ((Get-Date) -lt $deadline) {
    $value = Get-ConfigValue 'sensorId'
    if ($value -match $uuidPattern) { $sensorId = $value; break }
    if ((Get-NewLogText) -match 'Registration was REJECTED') { $rejected = $true; break }
    Start-Sleep -Seconds 2
}

$svc = Get-Service -Name $ServiceName
if (-not $sensorId) {
    Write-Host ""
    # The sensor marks failures with these emoji. Built from code points: this
    # file has no BOM, so Windows PowerShell reads it as ANSI, not UTF-8.
    $failureMarks = "$([char]::ConvertFromUtf32(0x26D4))|$([char]::ConvertFromUtf32(0x274C))|Registration (FAILED|retry failed)"
    (Get-NewLogText) -split "`r?`n" | Where-Object { $_ -match $failureMarks } |
        Select-Object -Last 8 | ForEach-Object { Write-Host "  $_" }
    Write-Host ""
    if ($rejected) {
        # A rejected key never succeeds; stop the service rather than leave the
        # SCM restarting it every 10 seconds.
        # Disable first so a restart the SCM has already queued cannot start it.
        Set-Service -Name $ServiceName -StartupType Disabled -ErrorAction SilentlyContinue
        Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
        Write-Err "The control plane REJECTED the registration key (see above): it is invalid, expired, or already used."
        Write-Err "Generate a new key (Discovery -> Sensors & Agents -> Register) and re-run this installer with it."
        Write-Info "The sensor service has been stopped and disabled."
    } else {
        if ($startError) { Write-Err "Starting the service failed: $startError" }
        Write-Err "The sensor did not register within ${timeoutSeconds}s (service status: $($svc.Status))."
        Write-Err "Check that $Url is reachable from this host."
        Write-Info "Log: $LogFile"
    }
    exit 1
}
if ($svc.Status -ne 'Running') {
    Write-Err "The sensor registered but the service is not running (status: $($svc.Status))."
    Write-Info "Log: $LogFile"
    exit 1
}

Write-Host ""
Write-Info "Sensor registered and running."
Write-Info "Sensor ID     : $sensorId"
Write-Info "Sensor version: $SensorVersion"
Write-Host ""
Write-Host "Management:" -ForegroundColor Cyan
Write-Host "  Status:  Get-Service $ServiceName"
Write-Host "  Logs:    Get-Content -Tail 50 -Wait '$LogFile'"
Write-Host "  Events:  Get-WinEvent -FilterHashtable @{LogName='Application'; ProviderName='$ServiceName'} -MaxEvents 20"
Write-Host "  Stop:    Stop-Service $ServiceName"
Write-Host "  Restart: Restart-Service $ServiceName"
