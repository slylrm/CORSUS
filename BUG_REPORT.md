# Bug Report

## Fixed
1. Fingerprint findings bulk insert only processed last item
   - Cause: loop body indentation in insert_fingerprint_findings.
   - Fix: move serialization and mapping inside the loop.
   - File: backend/app/models.py

2. Domain verification token not enforced on scan creation
   - Cause: API accepted token but never checked.
   - Fix: enforce token presence and verified status when required.
   - File: backend/app/api/scans.py

3. Domain verification endpoints accepted invalid domain formats
   - Cause: domain input allowed scheme or path.
   - Fix: normalize and validate domain strings.
   - File: backend/app/api/verification.py

4. WhatWeb JSON output path used /tmp on Windows
   - Cause: hardcoded /tmp path.
   - Fix: write logs to workspace whatweb_output directory.
   - File: backend/app/tools/discovery/whatweb_wrapper.py

5. Dir scanner default wordlist path was Linux-only
   - Cause: /usr/share/wordlists/dirb/common.txt.
   - Fix: default to repo wordlists/common.txt with fallback.
   - File: backend/app/tools/discovery/dir_scanner_wrapper.py

6. Built-in wrappers used 0-100 confidence scores
   - Cause: confidence_score values in percent.
   - Fix: normalize to 0.0-1.0.
   - File: backend/app/tools/discovery/builtin_scanner_wrapper.py

7. UI findings rendering used innerHTML with untrusted data
   - Cause: dynamic HTML injection in scan UI and standalone frontend.
   - Fix: DOM-based rendering with textContent.
   - Files: backend/app/templates/scan.html, frontend/index.html, backend/app/static/app.js

8. Start script ignored .venv Python
   - Cause: start.ps1 only searched system Python.
   - Fix: prefer project .venv.
   - File: start.ps1

9. Result validator had duplicate methods and unreachable code
   - Cause: duplicated _is_known_false_positive and dead block after return.
   - Fix: consolidate and remove dead code.
   - File: backend/app/core/result_validator.py
