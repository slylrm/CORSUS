# Auto Fix Log

Date: 2026-04-17

- Fixed fingerprint findings bulk insert loop indentation (backend/app/models.py).
- Enforced domain verification checks on scan creation (backend/app/api/scans.py).
- Added domain normalization and validation for verification endpoints (backend/app/api/verification.py).
- Replaced unsafe innerHTML rendering in scan UI and standalone frontend (backend/app/templates/scan.html, frontend/index.html).
- Hardened findings rendering in app.js endpoint and findings summaries (backend/app/static/app.js).
- Normalized confidence scores to 0.0-1.0 in built-in wrappers (backend/app/tools/discovery/builtin_scanner_wrapper.py).
- Switched WhatWeb output log to workspace directory and parse from file (backend/app/tools/discovery/whatweb_wrapper.py).
- Defaulted dir scanner wordlist to repo wordlists (backend/app/tools/discovery/dir_scanner_wrapper.py).
- Preferred project .venv Python in start.ps1.
- Cleaned duplicate and dead logic in result validator (backend/app/core/result_validator.py).
- Updated WhatWeb wrapper tests to accept dynamic log paths (backend/tests/test_whatweb_wrapper.py).
