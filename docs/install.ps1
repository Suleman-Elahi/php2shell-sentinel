# PHP2Shell Sentinel — Windows PowerShell One-Line Installer
# Usage (Run in Elevated Administrator PowerShell):
#   irm https://suleman-elahi.github.io/php2shell-sentinel/install.ps1 | iex

$ErrorActionPreference = "Stop"

$BaseUrl = if ($env:SENTINEL_BASE_URL) { $env:SENTINEL_BASE_URL } else { "https://suleman-elahi.github.io/php2shell-sentinel" }
$InstallDir = "C:\Program Files\PHP2ShellSentinel"
$DataDir = "C:\ProgramData\php2shell-sentinel"
$BinPath = Join-Path $InstallDir "sentinel.exe"
$ConfigPath = Join-Path $DataDir "sentinel.json"

Write-Host "[*] Installing PHP2Shell Sentinel for Windows (CVE-2026-109618 / CVE-2026-109619 Defense Agent)..." -ForegroundColor Cyan

# Verify Administrator privileges
$CurrentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $CurrentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "[!] Please run PowerShell as Administrator before running this installer."
    exit 1
}

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null

$DownloadUrl = "$BaseUrl/downloads/sentinel-windows-amd64.exe"
Write-Host "[*] Downloading $DownloadUrl -> $BinPath ..."
Invoke-WebRequest -Uri $DownloadUrl -OutFile $BinPath -UseBasicParsing

if (-not (Test-Path $ConfigPath)) {
    $ConfigUrl = "$BaseUrl/downloads/sentinel.example.json"
    Write-Host "[*] Downloading default configuration to $ConfigPath ..."
    try {
        Invoke-WebRequest -Uri $ConfigUrl -OutFile $ConfigPath -UseBasicParsing
    } catch {
        Write-Warning "Could not download sample config; Sentinel will use built-in defaults."
    }
}

# Add InstallDir to Machine PATH if not already present
$MachinePath = [Environment]::GetEnvironmentVariable("Path", "Machine")
if ($MachinePath -notlike "*$InstallDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$MachinePath;$InstallDir", "Machine")
    $env:Path += ";$InstallDir"
}

Write-Host "[*] Running initial PHP host audit..." -ForegroundColor Cyan
& $BinPath check

Write-Host "[*] Installing and starting Windows Service (PHP2ShellSentinel)..." -ForegroundColor Cyan
if (Test-Path $ConfigPath) {
    & $BinPath install -config $ConfigPath
} else {
    & $BinPath install
}
& $BinPath start

Write-Host "[+] PHP2Shell Sentinel is installed and running as a Windows Service!" -ForegroundColor Green
Write-Host "    Mode:                out-of-band (proxy disabled by default; web ports unchanged)"
Write-Host "    Check live status:   sentinel.exe status"
Write-Host "    Check SCM service:   Get-Service PHP2ShellSentinel"
Write-Host "    Harden php.ini:      sentinel.exe harden"
Write-Host ""
Write-Host "[*] Optional in-line HTTP WAF:" -ForegroundColor Cyan
Write-Host "    Set proxy_enabled=true, listen_addr=127.0.0.1:8080, and a real backend_url"
Write-Host "    in $ConfigPath, then restart the service. Route public traffic to listen_addr;"
Write-Host "    do not expose the PHP backend directly."
