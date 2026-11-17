# Project Overview

## Summary
- WeppenTest is a FastAPI-based web security assessment platform.
- It provides scan orchestration, tool wrapper integration, and a UI for status and findings.
- Scan state and findings are persisted in SQLite.

## Architecture
- API layer: backend/app/api/*.py
- Core engine: backend/app/core/scanner.py with tool runner, validators, and correlation.
- Persistence: backend/app/core/persistence.py plus backend/app/models.py
- Tools: backend/app/tools/* wrappers for external and built-in scanners.
- UI: backend/app/templates with backend/app/static/app.js, plus frontend/index.html.
- Scripts: run_server.py, start.ps1, setup.ps1, setup.sh

## Data Flow
1. Client sends POST /api/v1/scans with target, scan_type, scope, authorization, and token.
2. ScannerEngine creates a scan and background tasks orchestrate tool wrappers.
3. Tool results are normalized, validated, and persisted.
4. Reports endpoints return summaries and detailed findings to the UI.

## External Dependencies
- External scanners: nmap, nuclei, nikto, sqlmap, wapiti, trivy, gitleaks, zap, amass.
- Python-only scanners for basic headers, SSL, and ports.
- Wordlists stored in /wordlists.

## Output Artifacts
- Tool outputs are stored in *_output folders.
- Reports are stored in /reports.
- Logs are written to /logs/weppentest.log.
