# API Validation

## POST /api/v1/scans
Required fields:
- target_url: valid http or https URL
- scan_type: quick | standard | deep | custom
- authorization_acknowledged: must be true
- scope_statement: min length 10

Optional:
- tools: list of tool ids
- domain_verification_token: required when DOMAIN_VERIFICATION_REQUIRED is true and target is not local

Validation behavior:
- 400 if authorization_acknowledged is not true
- 403 if domain verification is required and token is missing, invalid, expired, or unverified
- 409 if an active scan already exists for target

## GET /api/v1/scans/{scan_id}
- Returns status, progress, current tool, and findings summary.

## Domain Verification
- POST /api/v1/verification/request
  - Requires domain hostname only (no scheme or path).
  - Returns token and instructions.
- POST /api/v1/verification/verify
  - Requires domain and token.
  - Marks token verified on success.
- GET /api/v1/verification/status/{domain}
  - Returns latest verification state for domain.

## Notes
- Validation now normalizes domain inputs and rejects URL or path injection.
