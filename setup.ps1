param(
    [switch]$IncludeWorker,
    [switch]$IncludePostgres,
    [switch]$IncludePdf,
    [switch]$IncludeExternalTools,
    [string]$PythonPreference = "3.12"
)

$ErrorActionPreference = "Stop"
$ProjectRoot = $PSScriptRoot
$VenvPath = Join-Path $ProjectRoot ".venv"
$PythonExe = $null
$CandidateVersions = @($PythonPreference, "3.12", "3.11", "3.13") | Select-Object -Unique

Write-Host "WeppenTest Platform - Environment Setup" -ForegroundColor Cyan
Write-Host "======================================" -ForegroundColor Cyan
Write-Host ""

foreach ($version in $CandidateVersions) {
    try {
        $resolved = & py "-$version" -c "import sys; print(sys.executable)" 2>$null
        if ($LASTEXITCODE -eq 0 -and $resolved) {
            $PythonExe = $resolved.Trim()
            break
        }
    } catch {
    }
}

if (-not $PythonExe) {
    Write-Host "No compatible Python interpreter found." -ForegroundColor Red
    Write-Host "Install Python 3.12 and run this script again." -ForegroundColor Yellow
    Write-Host "Recommended command: winget install -e --id Python.Python.3.12" -ForegroundColor Gray
    exit 1
}

$PythonVersion = & $PythonExe -c "import platform; print(platform.python_version())"
Write-Host "Using Python: $PythonExe" -ForegroundColor Green
Write-Host "Version: $PythonVersion" -ForegroundColor Green

if ($PythonVersion.StartsWith("3.13")) {
    Write-Host "Python 3.13 is supported with the updated pins, but Python 3.12 remains the preferred production baseline." -ForegroundColor Yellow
}

if (Test-Path $VenvPath) {
    Write-Host "Removing existing virtual environment..." -ForegroundColor Yellow
    Remove-Item -Recurse -Force $VenvPath
}

Write-Host "Creating clean virtual environment..." -ForegroundColor Green
& $PythonExe -m venv $VenvPath

$VenvPython = Join-Path $VenvPath "Scripts\python.exe"

Write-Host "Upgrading pip, setuptools, wheel..." -ForegroundColor Green
& $VenvPython -m pip install --upgrade pip setuptools wheel

Write-Host "Installing runtime and dev dependencies..." -ForegroundColor Green
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
Write-Host "Run tests: .\.venv\Scripts\python.exe -m pytest backend\tests\test_scanner_refactoring.py -q" -ForegroundColor Gray
