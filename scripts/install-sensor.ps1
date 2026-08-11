<#
.SYNOPSIS
    Vista Platform Sensor installer for Windows.

.DESCRIPTION
    Windows counterpart to install-sensor.sh. Registers the sensor with the
    control plane, writes the canonical sensor config, installs the sensor as a
    Windows service that starts on boot and restarts on failure, then starts it.

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

if ([string]::IsNullOrWhiteSpace($Name)) {
    $Name = "sensor-$($env:COMPUTERNAME)-$(Get-Date -Format 'yyyyMMdd')"
}

Write-Host ""
Write-Host "Vista Platform Sensor Installer (Windows)" -ForegroundColor Cyan
Write-Host "=========================================" -ForegroundColor Cyan
Write-Info "Control plane : $Url"
Write-Info "Sensor name   : $Name"
Write-Info "IP address    : $IP"
Write-Info "Profile       : $Profile"
Write-Info "Install dir   : $InstallDir"
Write-Host ""

# --- Layout ----------------------------------------------------------------
$CertsDir  = Join-Path $InstallDir "certs"
$DataDir   = Join-Path $InstallDir "data"
$ConfigPath = Join-Path $InstallDir "sensor-config.yaml"
New-Item -ItemType Directory -Force -Path $InstallDir, $CertsDir, $DataDir | Out-Null

Write-Info "Installing sensor binary..."
Copy-Item -Force $BinarySource (Join-Path $InstallDir "crypto-sensor.exe")

# --- Register with the control plane --------------------------------------
# We register here (rather than via the service's --register) so cert
# acquisition fails loudly at install time instead of crash-looping the
# service. The service then runs with the certs already on disk.
Write-Info "Registering sensor with control plane..."

$interfaceList = @()
if (-not [string]::IsNullOrWhiteSpace($Interfaces)) {
    $interfaceList = $Interfaces.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
}

$payload = @{
    registration_key   = $Key
    name               = $Name
    description        = "Sensor installed on $($env:COMPUTERNAME)"
    platform           = "windows"
    version            = "1.0.0"
    profile            = $Profile
    network_interfaces = $interfaceList
    ip_address         = $IP
} | ConvertTo-Json

try {
    $resp = Invoke-RestMethod -Method Post -Uri "$Url/api/v1/sensor-manager/sensors/register" `
        -ContentType "application/json" -Body $payload
    if ($resp.client_cert)   { $resp.client_cert   | Out-File -Encoding ascii (Join-Path $CertsDir "client.crt") }
    if ($resp.client_key)    { $resp.client_key    | Out-File -Encoding ascii (Join-Path $CertsDir "client.key") }
    if ($resp.server_ca_cert){ $resp.server_ca_cert| Out-File -Encoding ascii (Join-Path $CertsDir "server-ca.crt") }
    Write-Info "Sensor registered; certificates written to $CertsDir"
} catch {
    Write-Err "Failed to register sensor with control plane: $($_.Exception.Message)"
    Write-Err "Check the control plane URL, network reachability, and that the registration code has not expired."
    exit 1
}

# --- Write the canonical sensor config ------------------------------------
# Flat camelCase keys — this is the schema sensor/internal/config.ConfigFile
# actually parses. (Nested control_plane:/url: is NOT read by the sensor.)
Write-Info "Writing configuration to $ConfigPath"
$ifaceYaml = "[]"
if ($interfaceList.Count -gt 0) {
    $ifaceYaml = "[" + (($interfaceList | ForEach-Object { "`"$_`"" }) -join ", ") + "]"
}
# Windows paths are written as single-quoted YAML scalars so backslashes are
# taken literally (no \\-escaping needed). url/key/name carry no backslashes, so
# double quotes are fine for them.
$configContent = @"
# Vista Platform Sensor configuration (generated by install-sensor.ps1)
sensorId: "$Name"
controlPlaneUrl: "$Url"
registrationKey: "$Key"
reportingIntervalSeconds: 30

capture:
  interfaces: $ifaceYaml
  activeProbing: true
  networkDiscovery: true

storage:
  dataPath: '$DataDir'

security:
  useTLS: true
  clientCertPath: '$CertsDir\client.crt'
  clientKeyPath: '$CertsDir\client.key'
  serverCACertPath: '$CertsDir\server-ca.crt'
"@
$configContent | Out-File -Encoding utf8 -Force $ConfigPath

# --- Install + start the Windows service ----------------------------------
# Auto-start (survives reboot / maintenance) + restart-on-failure = the Windows
# equivalent of systemd `WantedBy=multi-user.target` + `Restart=always`.
Write-Info "Installing Windows service '$ServiceName'..."
$binPath = "`"$InstallDir\crypto-sensor.exe`" --verbose -config `"$ConfigPath`""

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Write-Warn "Service already exists — stopping and reconfiguring."
    Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue
    # sc.exe is the reliable way to rewrite binPath on an existing service.
    sc.exe config $ServiceName binPath= "$binPath" start= auto | Out-Null
} else {
    New-Service -Name $ServiceName -DisplayName $ServiceDisplay `
        -BinaryPathName $binPath -StartupType Automatic `
        -Description "Vista Platform passive crypto-discovery sensor" | Out-Null
}

# Restart on crash: reset failure count daily, restart after 10s on each of the
# first three failures.
sc.exe failure $ServiceName reset= 86400 actions= restart/10000/restart/10000/restart/10000 | Out-Null

Write-Info "Starting service..."
Start-Service -Name $ServiceName

Start-Sleep -Seconds 2
$svc = Get-Service -Name $ServiceName
if ($svc.Status -eq 'Running') {
    Write-Host ""
    Write-Info "Sensor is running."
    Write-Host ""
    Write-Host "Management:" -ForegroundColor Cyan
    Write-Host "  Status:  Get-Service $ServiceName"
    Write-Host "  Logs:    Get-EventLog -LogName Application -Source $ServiceName  (or check $DataDir)"
    Write-Host "  Stop:    Stop-Service $ServiceName"
    Write-Host "  Restart: Restart-Service $ServiceName"
} else {
    Write-Err "Service installed but not running (status: $($svc.Status))."
    Write-Err "Inspect with: Get-Service $ServiceName ; check $DataDir for logs."
    exit 1
}
