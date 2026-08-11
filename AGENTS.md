# Detector guidance

This repository owns the RF/TCN detector, deterministic policy, safe crawler,
API, and the bounded escalation from uncertain evidence to the standalone
agentic reviewer.

## Invariants

- Preserve `legitimate`, `phishing`, `suspicious`, and `crawl_failed`.
- Failed, blocked, partial, empty, timeout, and non-HTML crawls must never be
  converted into phishing or legitimate content verdicts.
- Preserve public-address validation for initial URLs, redirects, final URLs,
  browser requests, and client-supplied browser evidence.
- Keep the exact ordered 85-feature RF schema and the hostname-only TCN input
  contract synchronized with their serialized artifacts.
- `weak_feed` data is stress-test-only. Never fit, calibrate, select policy, or
  make formal accuracy claims from it.
- Keep registrable-domain isolation across train, calibration, policy, and the
  untouched test split.
- The agent is advisory and is called only for usable uncertain evidence. Its
  score must not be blended into calibrated RF/TCN scores.
- Do not commit `.env`, API keys, raw HTML, runtime SQLite databases, result
  stores, downloaded feeds, or release image archives.

## Verification

Run from this directory:

```powershell
$env:PYTHONPATH = "src"
.venv\Scripts\python.exe -m pytest
.venv\Scripts\python.exe scripts\validate_release.py
```

Docker integration tests must use the packaged mock OpenRouter service. Live
crawling, feed downloads, model retraining, browser installation, and paid LLM
calls are opt-in operations.
