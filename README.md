# PersianPhish Real-World Detector V3

Current service release: **v3.1.0**. The integrated stack pins
`agentic-phishing-review` **v1.3.0** and is compatible with the optional backend
mode in `phishingshield-persian` **v3.6.0**. See
[`deploy/COMPATIBILITY.json`](deploy/COMPATIBILITY.json) for the machine-readable
contract.

This package turns the paper dataset pipeline into a conservative URL detection service. It fixes the failure mode where an HTTP 403 page was treated as the requested website, separates trusted labels from broad blocklist captures, and combines a calibrated Random Forest, a byte-level URL TCN, local reputation, browser evidence, and the standalone bounded agentic review service.

## Output contract

| Verdict | Meaning | Caller action |
|---|---|---|
| `legitimate` | Evidence is inside the calibrated safe region. | Allow under the caller's normal policy. |
| `phishing` | Exact threat-intel match or high-confidence corroborated detection. | Block/quarantine. |
| `suspicious` | Evidence is usable but uncertain, out of distribution, or models disagree. | Queue review; do not call it phishing. |
| `crawl_failed` | The requested page was not observed reliably. | Retry with browser/client evidence; do not infer a label. |

An access-denied, challenge, timeout, empty, or broken page is never classified as phishing content.

## Decision flow

1. Canonicalize and SSRF-check the URL.
2. Check exact local phishing intelligence.
3. Fetch HTML and reject blocked/error/non-HTML responses.
4. Use pooled Chromium when HTTP evidence is incomplete or the model is uncertain.
5. Extract the fixed 85-feature RF schema and the fixed 512-byte TCN hostname
   input. The TCN receives only the normalized full hostname (including a
   subdomain), never a path, query, fragment, scheme, or port.
6. Apply RF/TCN calibration, OOD gating, and separate legitimate/phishing thresholds.
7. Use verified benign history only as corroboration; it cannot override exact phishing intelligence or risky credential/form evidence.
8. Send only usable, uncertain cases to the internal LangGraph/OpenRouter review service. The detector supplies the already-observed DOM and optional official-reference HTML; confident and failed cases never call the agent.
9. Keep unresolved cases in the SQLite review queue.

## Current artifacts

| File | Purpose |
|---|---|
| `artifacts/v3/detector_v3_tcn.joblib` | RF, ensemble calibration, thresholds, schema, and metadata |
| `artifacts/v3/url_tcn.onnx` | Portable URL TCN inference model |
| `artifacts/v3/url_tcn.pt` | Training checkpoint; not needed by the API |
| `var/intel.sqlite3` | Exact phishing indicators and verified benign host history |
| `data/processed/realworld_v3_features.csv` | Auditable training/evaluation feature table |
| `data/processed/realworld_v3_quality_issues.csv` | Quarantine and quality audit |

The blind generated-technique test contains 935 verified legitimate pages and 845 generated phishing pages from source domains absent from training. At the policy threshold, the final ensemble has 0.9987 precision, 0.9207 recall, and 1 false positive. These are generated-technique benchmark results, not a claim of equivalent open-world performance. The artifact intentionally reports `production_ready=false` because 935 benign test pages cannot statistically prove a 0.1% false-positive target.

## Local setup

Use a clean Python 3.9-3.12 environment. On Windows, placing the package under an ASCII-only path avoids older `setuptools` path-encoding failures.

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-browser.txt
python -m playwright install chromium
$env:PYTHONPATH = "src"
```

Linux:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[browser]'
playwright install --with-deps chromium
```

## Run

```powershell
$env:PYTHONPATH = "src"
python -m persianphish_detector detect --url https://soft98.ir
python -m persianphish_detector serve --host 127.0.0.1 --port 8088
```

```bash
curl -s http://127.0.0.1:8088/health
curl -s -X POST http://127.0.0.1:8088/v1/detect \
  -H 'content-type: application/json' \
  -d '{"url":"https://soft98.ir"}'
```

The API accepts optional browser evidence from a trusted client. Its schema rejects cookies, request headers, form values, and unknown fields.

Optional `agent_references` accepts at most three official reference candidates (2 MB each, 5 MB total). Raw suspicious/reference HTML exists only in memory while the two services process the request; detector results and both SQLite stores contain sanitized hashes, scores, codes, reasons, and timings only.

## Integrated Docker stack

The production entry point is the detector on `127.0.0.1:8088`; the review UI/API is separately available on `127.0.0.1:8090`. Only uncertain detector results cross the internal service boundary.

Clone the detector and reviewer as sibling directories using their repository
names. The Compose file pins the reviewer version and builds both services:

```text
workspace/
  phishing-detection-engine/
  agentic-phishing-review/
```

```bash
cp .env.example .env
# Set OPENROUTER_API_KEY and a long random INTERNAL_REVIEW_API_KEY.
docker compose -f deploy/compose.yaml up -d --build
curl --fail http://127.0.0.1:8088/ready
```

See [Integrated deployment](deploy/INTEGRATED.md) for startup, smoke testing, backup, and rollback.

The browser extension remains independently installable and offline by
default. Its v3.6.0 Options page can explicitly enable escalation of local
`suspicious` results to this API. See
[Extension integration](docs/EXTENSION_INTEGRATION.md).

## Rebuild artifacts

```powershell
python -m persianphish_detector.dataset --workspace .. `
  --output data/processed/realworld_v3_features.csv `
  --issues-output data/processed/realworld_v3_quality_issues.csv `
  --workers 6

python -m persianphish_detector train `
  --dataset data/processed/realworld_v3_features.csv `
  --output artifacts/v3/detector_v3.joblib `
  --n-jobs -1

python -m persianphish_detector train-tcn `
  --dataset data/processed/realworld_v3_features.csv `
  --rf-artifact artifacts/v3/detector_v3.joblib

python -m persianphish_detector ingest --format verified-benign `
  --file data/processed/realworld_v3_features.csv --db var/intel.sqlite3
```

## Threat intelligence and review

```powershell
python -m persianphish_detector ingest --format openphish --file feeds/openphish.txt
python -m persianphish_detector ingest --format phishtank --file feeds/phishtank.json
python -m persianphish_detector review --db var/review.sqlite3 --limit 50
python -m persianphish_detector review --db var/review.sqlite3 `
  --resolve REQUEST_ID --label legitimate --note "Analyst verified ownership"
python -m persianphish_detector review --db var/review.sqlite3 `
  --export data/feedback/resolved_reviews.csv
```

## Validation

```powershell
$env:PYTHONPATH = "src"
python -m pytest
python scripts/validate_release.py
```

See [Architecture](docs/ARCHITECTURE.md), [Real-World Findings](docs/REAL_WORLD_FINDINGS.md), [Data Card](docs/DATA_CARD.md), [Model Card](docs/MODEL_CARD.md), [Operations](docs/OPERATIONS.md), and [Acceptance](docs/ACCEPTANCE.md).
