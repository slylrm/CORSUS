# WeppenTest Platform

AI-free, deterministic web application security testing platform.

GitHub repository: [github.com/slylrm/corsus](https://github.com/slylrm/corsus)

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

### Docker (optional)

```powershell
docker compose up --build -d app
# Include the isolated OWASP ZAP service:
docker compose --profile scanners up --build -d
```

The Docker app binds to `127.0.0.1:8000`; native Windows setup remains supported. See [Docker setup](docs/DOCKER_SETUP.md) and the [Security Tools Arsenal](docs/SECURITY_TOOLS.md). The central local inventory is available at `/api/v1/tools/arsenal`.

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
.\.venv\Scripts\python.exe -m pytest backend\tests -q
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

## Documentation

- [Documentation index](docs/README.md)
- [Project cleanup and retained items](docs/PROJECT_CLEANUP.md)
- [Security Tools Arsenal](docs/SECURITY_TOOLS.md)
- [Tool arguments and manager](docs/TOOL_ARGUMENTS.md)
- [Docker setup](docs/DOCKER_SETUP.md)
- [LLM security module](docs/LLM_SECURITY.md)
- [Browser automation](docs/BROWSER_AUTOMATION.md)
- [Project overview](PROJECT_OVERVIEW.md)
- [Security audit](SECURITY_AUDIT.md)
- [Historical web pentest tools handbook](<Kapsamlı Web Pentest Araçları Dokümantasyonu.md>)

## Frontend

The application UI is served from `backend/app/templates` with assets from `backend/app/static`. `frontend/index.html` remains an optional standalone development page; when served separately on ports `5173`, `3000`, or `5500`, it calls the backend at `127.0.0.1:8000`.

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

### Nikto on Windows

Nikto source execution requires Perl. Set `NIKTO_PATH`, `NIKTO_GIT_SOURCE`, and `PERL_PATH` in your local, ignored `.env` as needed. The registry also checks supported bundled and sibling source locations. Do not add local secrets or machine-specific paths to Git.
