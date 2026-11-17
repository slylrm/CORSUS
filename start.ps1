#!/usr/bin/env pwsh
<#
.SYNOPSIS
    WeppenTest Platform - Quick Start Script
#>

$ErrorActionPreference = "Stop"
$Env:PYLAUNCHER_ALLOW_INSTALL = "0"
$Env:PYLAUNCHER_ALWAYS_INSTALL = "0"
$ProjectRoot = $PSScriptRoot
$EnvFile = Join-Path $ProjectRoot ".env"
$BinDir = Join-Path $ProjectRoot "backend\app\bin"
$HostValue = "127.0.0.1"
$PortValue = 8000

function Test-PortInUse {
    param(
        [string]$HostName,
        [int]$PortNumber
    )
    try {
        $conns = Get-NetTCPConnection -LocalPort $PortNumber -State Listen -ErrorAction Stop
        if (-not $conns) {
            return $false
        }
        foreach ($conn in $conns) {
            if ($conn.LocalAddress -eq "0.0.0.0" -or $conn.LocalAddress -eq "::" -or $conn.LocalAddress -eq $HostName -or $HostName -eq "127.0.0.1") {
                return $true
            }
        }
        return $true
    } catch {
        return $false
    }
}

function Test-HealthEndpoint {
    param(
        [string]$HostName,
        [int]$PortNumber
    )
    try {
        $url = "http://$HostName`:$PortNumber/health"
        $resp = Invoke-WebRequest -UseBasicParsing -Uri $url -TimeoutSec 2
        return ($resp.StatusCode -ge 200 -and $resp.StatusCode -lt 500)
    } catch {
        return $false
    }
}

function Find-FreePort {
    param(
        [string]$HostName,
        [int]$StartPort,
        [int]$MaxAttempts = 20
    )
    for ($i = 0; $i -lt $MaxAttempts; $i++) {
        $candidate = $StartPort + $i
        if (-not (Test-PortInUse -HostName $HostName -PortNumber $candidate)) {
            return $candidate
        }
    }
    throw "No available port found in range $StartPort-$($StartPort + $MaxAttempts - 1)"
}

if (Test-Path $EnvFile) {
    foreach ($line in Get-Content $EnvFile) {
        if ($line -match '^\s*API_HOST\s*=\s*(.+?)\s*$') {
            $HostValue = $matches[1].Trim('"')
        }
        if ($line -match '^\s*API_PORT\s*=\s*(.+?)\s*$') {
            $parsedPort = 0
            if ([int]::TryParse($matches[1].Trim('"'), [ref]$parsedPort)) {
                $PortValue = $parsedPort
            }
        }
    }
}

Write-Host "Starting WeppenTest Platform..." -ForegroundColor Cyan

# Set bin tool paths dynamically from project directory
$binTools = @{
    "NUCLEI_PATH"      = Join-Path $BinDir "nuclei.exe"
    "GITLEAKS_PATH"    = Join-Path $BinDir "gitleaks.exe"
    "NIKTO_PATH"       = Join-Path $BinDir "nikto\program\nikto.pl"
    "NIKTO_GIT_SOURCE" = Join-Path $BinDir "nikto"
}
foreach ($tool in $binTools.GetEnumerator()) {
    if (Test-Path $tool.Value) {
        Set-Item -Path "Env:$($tool.Key)" -Value $tool.Value
    }
}

# Optional bundled/command-resolved tool paths
$optionalTools = @(
    @{ Key = "AMASS_PATH"; Candidates = @((Join-Path $BinDir "amass.exe"), "amass") },
    @{ Key = "TRIVY_PATH"; Candidates = @((Join-Path $BinDir "trivy.exe"), "trivy") },
    @{ Key = "SEMGREP_PATH"; Candidates = @((Join-Path $ProjectRoot ".venv\\Scripts\\semgrep.exe"), "semgrep") },
    @{ Key = "SQLMAP_PATH"; Candidates = @((Join-Path $BinDir "sqlmap.bat"), "sqlmap") },
    @{ Key = "WHATWEB_PATH"; Candidates = @("whatweb") },
    @{ Key = "DIRSEARCH_PATH"; Candidates = @("dirsearch") }
)
foreach ($entry in $optionalTools) {
    if ([System.Environment]::GetEnvironmentVariable($entry.Key, "Process")) {
        continue
    }
    foreach ($candidate in $entry.Candidates) {
        if (Test-Path $candidate) {
            Set-Item -Path "Env:$($entry.Key)" -Value (Resolve-Path $candidate).Path
            break
        }
        $cmd = Get-Command $candidate -ErrorAction SilentlyContinue
        if ($cmd -and $cmd.Source -and ($cmd.Source -notlike "*\\WindowsApps\\*")) {
            Set-Item -Path "Env:$($entry.Key)" -Value $cmd.Source
            break
        }
    }
}

# External-tool auto discovery (niktowap bundles)
$wapitiCandidates = @(
    (Join-Path $ProjectRoot "..\niktowap\wapiti-master\bin\wapiti"),
    (Join-Path $ProjectRoot "..\niktowap\wapiti-master\bin\wapiti.py"),
    (Join-Path $ProjectRoot "backend\app\bin\wapiti\bin\wapiti"),
    (Join-Path $ProjectRoot "backend\app\bin\wapiti\bin\wapiti.py")
)
foreach ($candidate in $wapitiCandidates) {
    if (Test-Path $candidate) {
        Set-Item -Path "Env:WAPITI_PATH" -Value (Resolve-Path $candidate).Path
        break
    }
}

$niktoGitCandidates = @(
    (Join-Path $ProjectRoot "..\niktowap\nikto-main"),
    (Join-Path $ProjectRoot "backend\app\bin\nikto_backup_20260415_140346"),
    (Join-Path $ProjectRoot "backend\app\bin\nikto")
)
foreach ($candidate in $niktoGitCandidates) {
    if (Test-Path $candidate) {
        Set-Item -Path "Env:NIKTO_GIT_SOURCE" -Value (Resolve-Path $candidate).Path
        break
    }
}

# Stable system tool paths (no username, independent of user)
$systemTools = @{
    "PERL_PATH" = @(
        "C:\Strawberry\perl\bin\perl.exe",
        "C:\Perl64\bin\perl.exe",
        "C:\Perl\bin\perl.exe"
    )
    "NMAP_PATH" = @(
        "C:\Program Files (x86)\Nmap\nmap.exe",
        "C:\Program Files\Nmap\nmap.exe"
    )
}
foreach ($entry in $systemTools.GetEnumerator()) {
    # Only set if not already set by .env
    if (-not [System.Environment]::GetEnvironmentVariable($entry.Key, "Process")) {
        foreach ($candidate in $entry.Value) {
            if (Test-Path $candidate) {
                Set-Item -Path "Env:$($entry.Key)" -Value $candidate
                break
            }
        }
    }
}

$Env:PYTHONUNBUFFERED = "1"
$RuntimeTempDir = Join-Path $ProjectRoot ".tmp\runtime-temp"
if (-not (Test-Path $RuntimeTempDir)) {
    New-Item -ItemType Directory -Path $RuntimeTempDir -Force | Out-Null
}
$Env:TEMP = $RuntimeTempDir
$Env:TMP = $RuntimeTempDir

# Port conflict guard: if already running, reuse existing service instead of crashing.
if (Test-PortInUse -HostName $HostValue -PortNumber $PortValue) {
    if (Test-HealthEndpoint -HostName $HostValue -PortNumber $PortValue) {
        Write-Host "Server already running at http://$HostValue`:$PortValue/" -ForegroundColor Yellow
        Write-Host "Dashboard:  http://$HostValue`:$PortValue/" -ForegroundColor White
        Write-Host "API Docs:   http://$HostValue`:$PortValue/docs" -ForegroundColor White
        Write-Host "Health:     http://$HostValue`:$PortValue/health" -ForegroundColor White
        return
    }
    $newPort = Find-FreePort -HostName $HostValue -StartPort ($PortValue + 1)
    Write-Host "Port $PortValue is busy. Switching to free port $newPort." -ForegroundColor Yellow
    $PortValue = $newPort
}

Write-Host "Server URL: http://$HostValue`:$PortValue" -ForegroundColor Green
Write-Host "Dashboard:  http://$HostValue`:$PortValue/" -ForegroundColor White
Write-Host "API Docs:   http://$HostValue`:$PortValue/docs" -ForegroundColor White
Write-Host "Health:     http://$HostValue`:$PortValue/health" -ForegroundColor White
Write-Host ""
Write-Host "Press CTRL+C to stop the server" -ForegroundColor Yellow
Write-Host "Live log file: $ProjectRoot\logs\weppentest.log" -ForegroundColor White
Write-Host ""

$PythonExe = $null
$PythonCandidates = @(
    (Join-Path $ProjectRoot ".venv\Scripts\python.exe"),
    (Join-Path $Env:LOCALAPPDATA "Programs\Python\Python313\python.exe"),
    (Join-Path $Env:LOCALAPPDATA "Programs\Python\Python312\python.exe")
)

foreach ($candidate in $PythonCandidates) {
    if (Test-Path $candidate) {
        $PythonExe = $candidate
        break
    }
}

if ($PythonExe) {
    $Env:API_HOST = $HostValue
    $Env:API_PORT = $PortValue
    & $PythonExe (Join-Path $ProjectRoot "run_server.py")
}
else {
    throw "Project Python not found (.venv or local Python path). To avoid Microsoft Store alias popups, py/python alias fallback is disabled. Run .\\setup.ps1 and retry."
}
