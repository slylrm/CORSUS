# Production Readiness

## Current Status
Not production ready.

## Release Blockers
1. No authentication or access control for API or UI.
2. No per-scan ownership or tenancy isolation.
3. External tool execution relies on local binaries without sandboxing.
4. TLS verification is disabled for some built-in HTTP checks (verify=False).
5. Legacy templates still use innerHTML; ensure only hardened UI is exposed.

## Pre-Production Checklist
- Add auth (API key or OAuth) and role-based access controls.
- Enforce target allowlist or denylist and legal acknowledgement logging.
- Introduce worker queue and resource limits per scan or tool.
- Implement monitoring, structured logging, and alerting.
- Define artifact retention policy and cleanup jobs.
- Add CI test coverage for core scanning flows.

## Notes
- This assessment did not execute load, stress, or security penetration tests on the platform itself.
