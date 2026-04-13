# WeppenTest Platform

AI-free, deterministic web application security testing platform.

## Quick Start

Preferred Python: `3.12`
Supported Python: `3.13` with the updated dependency pins in this repo.

Why this matters:
- Older `pydantic` / `pydantic-core` pins often miss Python 3.13 wheels.
- When that happens, `pip` falls back to a source build.
- `pydantic-core` is written in Rust, so the build fails if Rust is not installed.

### Windows setup

```powershell
.\setup.ps1
```

Optional dependency groups:

```powershell
.\setup.ps1 -IncludeWorker -IncludePostgres -IncludeExternalTools
.\setup.ps1 -IncludePdf
```

### Start the app

```powershell
.\start.ps1
```

Backend URLs:
- Dashboard: `http://127.0.0.1:8000/`
- API docs: `http://127.0.0.1:8000/docs`
- Health: `http://127.0.0.1:8000/health`

### Manual start

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload
```

### Tests

```powershell
.\.venv\Scripts\python.exe -m pytest backend\tests\test_scanner_refactoring.py -q
.\.venv\Scripts\python.exe -m pytest backend\tests\test_e2e.py -q
```

## Dependency Layout

Core runtime:
- `backend/requirements.txt`

Dev and test:
- `backend/requirements-dev.txt`

Optional worker:
- `backend/requirements-worker.txt`

Optional PostgreSQL:
- `backend/requirements-postgres.txt`

Optional PDF export:
- `backend/requirements-pdf.txt`

Optional external scanner integrations:
- `backend/requirements-tools.txt`

## Environment

The sample env file is `.env.example`.

Default local settings:

```env
API_HOST=127.0.0.1
API_PORT=8000
DATABASE_URL=sqlite+aiosqlite:///./weppentest.db
```

`CORS_ORIGINS` can be provided as either:
- a comma-separated list
- a JSON array

## Frontend

The standalone frontend in `frontend/index.html` now works in both modes:
- served by the backend on the same origin
- served separately on ports `5173`, `3000`, or `5500`, while calling the backend on `127.0.0.1:8000`

## Troubleshooting

### Clean rebuild

```powershell
Remove-Item -Recurse -Force .\.venv
.\setup.ps1
```

### If Python 3.12 is missing

```powershell
winget install -e --id Python.Python.3.12
```

### If you must build Rust-based packages from source

```powershell
winget install -e --id Rustlang.Rustup
rustup default stable
```
