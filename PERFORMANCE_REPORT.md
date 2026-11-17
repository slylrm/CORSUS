# Performance Report

## Observations
- Scan progress polling is set to 2s in the UI; with many concurrent users this can increase load.
- Full raw outputs are stored in memory and persisted for each tool; large scans can grow quickly.
- Some wrappers run external processes synchronously; long-running tools can tie up worker slots.

## Recommendations
1. Add server-sent events or WebSocket updates to reduce polling overhead.
2. Apply per-scan output size limits or stream large tool outputs to files only.
3. Introduce backpressure or queueing for external tools and cap concurrent tool runs.
4. Cache and paginate findings on the API for large scans (UI pagination exists but is not enforced server-side).

## Status
- No performance tests were executed in this pass.
