# Project cleanup report

## Removed

- `backend/app/tools/discovery/zap_scanner_wrapper_async.py` — no imports, route references, test references, or runtime selection references existed. The scanner registry and scan construction use `zap_scanner_wrapper.py`; the async duplicate wrapped an event loop synchronously and was not a viable runtime alternative.
- `backend/app/templates/index_new.html` and `report_new.html` — neither is selected by any FastAPI route or referenced by application code, JavaScript, configuration, or tests. The active routes use `index.html`, `scan.html`, `recon.html`, and `health.html`.

## Moved

- `README_OLD.md` → `docs/archive/README_OLD.md` — historical instructions had no inbound project references; current setup is documented in the root README.

## Preserved after reference review

- `backend/app/templates/scan_old.html`, `scan_new.html`, `assessment.html`, and `report.html` are not selected by current route handlers. They are staged user changes and audit/report material calls them out; they remain intact for review.
- `backend/app/tools/examples/header_scanner.py` is example code, not part of scanner registration. It remains in the examples package.
- `backend/app/bin/nikto_backup_20260415_140346` and `backend/app/bin/sqlmap` are retained because local tool discovery/launch can use bundled source trees.
- Root project/audit reports and the comprehensive tools handbook were already staged. They remain at their paths; this index categorizes them without rewriting or unstaging them.
- `frontend/index.html` remains the optional standalone UI. The served application uses `backend/app/templates` and `backend/app/static`.
- `setup.sh`, `setup.ps1`, `start.ps1`, and `run_server.py` are retained; platform scripts and launcher references were confirmed.

## Unused or uncertain candidates retained

- `backend/app/core/report_generator.py`, `backend/app/core/adapters/depth_controller.py`, and `backend/app/core/intelligence/verification_probes.py` have no direct call/import references in the current source tree. They are substantial reporting/scanner components, so they were preserved pending an owner decision and integration review.
- `backend/app/tasks/scan_tasks.py` defines optional Celery tasks but has no current app import or autodiscovery reference. The module was retained because it belongs to the declared optional worker feature; verify worker startup/task registration before relying on those tasks.
- `backend/app/shims/*` files are staged additions with no direct current import references. They were preserved as user work rather than removed.
- `backend/app/tools/examples/header_scanner.py` is self-contained example code, not a registered scanner.

## User data and local state retained

The local `.env`, SQLite database, reports, scanner output directories, wordlists, and `.tmp` contents were preserved. `.tmp` contains scanner runtime/template data and package/test temporary files, so its contents were not treated as safe-to-delete cache. Python/pytest cache directories are ignored by Git and were left intact.

## Layout and reference updates

Added a documentation index at `docs/README.md`, linked the current docs from the root README, corrected the frontend description to match the FastAPI template routes, and removed a README instruction pointing to a PowerShell file absent from the repository. No backend imports, application routes, runtime file paths, Docker paths, or install script locations were moved.

## Validation

The cleanup was followed by the full backend test suite, Python compilation, an API inventory smoke check, and Docker Compose YAML parsing. Docker engine execution remains environment-dependent; run `docker compose config` and `docker compose up --build` where Docker Desktop/Compose is installed.
