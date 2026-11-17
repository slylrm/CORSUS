# Security Audit

## Fixed Findings
1. High - Domain verification enforcement missing
   - Impact: scans could be started without verified ownership when required.
   - Fix: enforce token validation and expiry checks in scans API.
   - Evidence: backend/app/api/scans.py
2. Medium - Domain verification endpoints accepted URLs or paths
   - Impact: potential path or scheme injection into verification checks.
   - Fix: normalize and validate domain strings before DNS and HTTP checks.
   - Evidence: backend/app/api/verification.py
3. High - UI XSS risk from unescaped findings rendering
   - Impact: malicious content from scan data could inject HTML.
   - Fix: render findings with DOM APIs and normalize risk classes.
   - Evidence: backend/app/templates/scan.html, frontend/index.html, backend/app/static/app.js

## Open Findings / Residual Risk
- Low - TLS verification disabled for built-in HTTP checks (verify=False). This can allow MITM to influence scan results. Consider a config flag to enable verification by default.
- Medium - Legacy templates (assessment.html, report.html, scan_old.html, scan_new.html) still use innerHTML in JS. If these templates are exposed, apply the same sanitization approach or retire them.

## Notes
- External tools perform active scanning. Ensure authorization, legal terms, and operating mode constraints are enforced in production environments.
