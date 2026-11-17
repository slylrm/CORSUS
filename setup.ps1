param(
    [switch]$IncludeWorker,
    [switch]$IncludePostgres,
    [switch]$IncludePdf,
    [switch]$IncludeExternalTools,
    [switch]$RecreateVenv,
    [string]$PythonPreference = "3.12"
)

$ErrorActionPreference = "Stop"
$Env:PYLAUNCHER_ALLOW_INSTALL = "0"
$Env:PYLAUNCHER_ALWAYS_INSTALL = "0"
$ProjectRoot = $PSScriptRoot
$VenvPath = Join-Path $ProjectRoot ".venv"
$PythonExe = $null
$CandidatePythonPaths = @(
    (Join-Path $VenvPath "Scripts\python.exe"),
    (Join-Path $Env:LOCALAPPDATA "Programs\Python\Python312\python.exe"),
    (Join-Path $Env:LOCALAPPDATA "Programs\Python\Python313\python.exe"),
    (Join-Path $Env:LOCALAPPDATA "Programs\Python\Python311\python.exe")
)

Write-Host "WeppenTest Platform - Environment Setup" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

function Stop-VenvLockingProcesses {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VenvRoot
    )

    $resolvedVenv = [System.IO.Path]::GetFullPath($VenvRoot)
    $targets = @("python", "py", "uvicorn")
    foreach ($procName in $targets) {
        Get-Process -Name $procName -ErrorAction SilentlyContinue | ForEach-Object {
            try {
                if ($_.Path -and ([System.IO.Path]::GetFullPath($_.Path)).StartsWith($resolvedVenv, [System.StringComparison]::OrdinalIgnoreCase)) {
                    Write-Host "Stopping process $($_.ProcessName) (PID=$($_.Id)) locking .venv" -ForegroundColor Yellow
                    Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
                }
            } catch {
                # ignore processes whose Path cannot be resolved
            }
        }
    }
}

function Remove-VenvDirectory {
    param(
        [Parameter(Mandatory = $true)]
        [string]$VenvRoot
    )

    if (-not (Test-Path $VenvRoot)) {
        return
    }

    Stop-VenvLockingProcesses -VenvRoot $VenvRoot

    $maxAttempts = 3
    for ($attempt = 1; $attempt -le $maxAttempts; $attempt++) {
        try {
            Remove-Item -Recurse -Force $VenvRoot -ErrorAction Stop
            return
        } catch {
            if ($attempt -lt $maxAttempts) {
                Write-Host "Retrying virtualenv removal (attempt $($attempt + 1)/$maxAttempts)..." -ForegroundColor Yellow
                Start-Sleep -Seconds 2
                Stop-VenvLockingProcesses -VenvRoot $VenvRoot
                continue
            }
            throw
        }
    }
}

foreach ($candidate in $CandidatePythonPaths) {
    if (-not (Test-Path $candidate)) {
        continue
    }

    try {
        $resolved = (Resolve-Path $candidate).Path
        if ($resolved -match '\\WindowsApps\\') {
            continue
        }

        $PythonExe = $resolved
        break
    } catch {
    }
}

if (-not $PythonExe) {
    Write-Host "No compatible Python interpreter found." -ForegroundColor Red
    Write-Host "Install Python 3.12 or create .venv, then run this script again." -ForegroundColor Yellow
    Write-Host "Recommended command: winget install -e --id Python.Python.3.12" -ForegroundColor Gray
    exit 1
}

$PythonVersion = & $PythonExe -c "import platform; print(platform.python_version())"
Write-Host "Using Python: $PythonExe" -ForegroundColor Green
Write-Host "Version: $PythonVersion" -ForegroundColor Green

if ($PythonVersion.StartsWith("3.13")) {
    Write-Host "Python 3.13 is supported with the updated pins, but Python 3.12 remains the preferred production baseline." -ForegroundColor Yellow
}

if ((Test-Path $VenvPath) -and $RecreateVenv) {
    Write-Host "Removing existing virtual environment..." -ForegroundColor Yellow
    Remove-VenvDirectory -VenvRoot $VenvPath
}

if (-not (Test-Path $VenvPath)) {
    Write-Host "Creating virtual environment..." -ForegroundColor Green
    & $PythonExe -m venv $VenvPath
} else {
    Write-Host "Virtual environment already exists; reusing .venv" -ForegroundColor Yellow
}

$VenvPython = Join-Path $VenvPath "Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    throw "Virtual environment Python not found at $VenvPython"
}

Write-Host "Ensuring pip/setuptools/wheel are up to date..." -ForegroundColor Green
& $VenvPython -m pip install --upgrade pip setuptools wheel

Write-Host "Installing/updating runtime and dev dependencies..." -ForegroundColor Green
& $VenvPython -m pip install -r (Join-Path $ProjectRoot "backend\requirements-dev.txt")

if ($IncludeWorker) {
    Write-Host "Installing worker dependencies..." -ForegroundColor Green
    & $VenvPython -m pip install -r (Join-Path $ProjectRoot "backend\requirements-worker.txt")
}

if ($IncludePostgres) {
    Write-Host "Installing PostgreSQL dependencies..." -ForegroundColor Green
    & $VenvPython -m pip install -r (Join-Path $ProjectRoot "backend\requirements-postgres.txt")
}

if ($IncludePdf) {
    Write-Host "Installing PDF dependencies..." -ForegroundColor Green
    & $VenvPython -m pip install -r (Join-Path $ProjectRoot "backend\requirements-pdf.txt")
}

if ($IncludeExternalTools) {
    Write-Host "Installing external scanner integration dependencies..." -ForegroundColor Green
    & $VenvPython -m pip install -r (Join-Path $ProjectRoot "backend\requirements-tools.txt")
}

if (-not (Test-Path (Join-Path $ProjectRoot ".env"))) {
    Copy-Item (Join-Path $ProjectRoot ".env.example") (Join-Path $ProjectRoot ".env")
    Write-Host "Created .env from .env.example" -ForegroundColor Green
} else {
    Write-Host ".env already exists; leaving it in place." -ForegroundColor Yellow
}

New-Item -ItemType Directory -Force -Path `
    (Join-Path $ProjectRoot "logs"), `
    (Join-Path $ProjectRoot "reports"), `
    (Join-Path $ProjectRoot "nmap_output"), `
    (Join-Path $ProjectRoot "sqlmap_output") | Out-Null

Write-Host "Running import sanity check..." -ForegroundColor Green
& $VenvPython -c "import sys; sys.path.insert(0, 'backend'); import app.main; print('Import check: OK')"

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host "Activate: .\.venv\Scripts\Activate.ps1" -ForegroundColor Gray
Write-Host "Start app: .\start.ps1" -ForegroundColor Gray
Write-Host "Force clean rebuild: .\setup.ps1 -RecreateVenv" -ForegroundColor Gray
Write-Host "Run tests: .\.venv\Scripts\python.exe -m pytest backend\tests\test_scanner_refactoring.py -q" -ForegroundColor Gray
