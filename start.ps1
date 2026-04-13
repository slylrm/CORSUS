#!/usr/bin/env pwsh
<#
.SYNOPSIS
    WeppenTest Platform - Quick Start Script
#>

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$EnvFile = Join-Path $ProjectRoot ".env"
$VenvPath = Join-Path $ProjectRoot ".venv"
$ActivateScript = Join-Path $VenvPath "Scripts\Activate.ps1"
$PythonExe = Join-Path $VenvPath "Scripts\python.exe"
$HostValue = "127.0.0.1"
$PortValue = "8000"

if (-not (Test-Path $ActivateScript)) {
    Write-Host "Virtual environment not found. Run .\setup.ps1 first." -ForegroundColor Red
    exit 1
}

if (Test-Path $EnvFile) {
    foreach ($line in Get-Content $EnvFile) {
        if ($line -match '^\s*API_HOST\s*=\s*(.+?)\s*$') {
            $HostValue = $matches[1].Trim('"')
        }
        if ($line -match '^\s*API_PORT\s*=\s*(.+?)\s*$') {
            $PortValue = $matches[1].Trim('"')
        }
    }
}

Write-Host "Starting WeppenTest Platform..." -ForegroundColor Cyan
Write-Host "Activating virtual environment..." -ForegroundColor Yellow
& $ActivateScript

Write-Host "Server URL: http://$HostValue`:$PortValue" -ForegroundColor Green
Write-Host "Dashboard:  http://$HostValue`:$PortValue/" -ForegroundColor White
Write-Host "API Docs:   http://$HostValue`:$PortValue/docs" -ForegroundColor White
Write-Host "Health:     http://$HostValue`:$PortValue/health" -ForegroundColor White
Write-Host ""
Write-Host "Press CTRL+C to stop the server" -ForegroundColor Yellow
Write-Host ""

& $PythonExe -m uvicorn app.main:app --app-dir backend --host $HostValue --port $PortValue --reload
