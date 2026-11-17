# Missing Features

## Security and Access
- Authentication and authorization for API endpoints (no user or role model).
- Per-scan ownership and access control.
- API keys or session management for the UI.

## Operational
- Durable job queue and worker separation for long-running tools.
- Centralized audit log persistence beyond file logging.
- Retention and cleanup jobs for output artifacts.

## Product
- Scan scheduling and recurring scans.
- Export formats beyond HTML or JSON (PDF is referenced but not integrated).
- Notification system for scan completion or failure.

## Safety
- Configurable allowlist or denylist for targets.
- Explicit safe mode enforcement for active tools (sqlmap, wapiti, zap).
