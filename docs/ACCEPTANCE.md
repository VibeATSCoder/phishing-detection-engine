# Release Acceptance

## Automated gates

```powershell
$env:PYTHONPATH = "src"
python -m pytest
python scripts/validate_release.py
```

The release validator must report:

- `passed: true`
- no missing feature columns
- zero trusted groups crossing splits
- zero duplicate sample identifiers
- zero duplicate canonical URLs and zero absolute HTML paths
- zero weak-feed rows in training
- finite ONNX probabilities
- the expected model version and `production_ready` state

## API gates

1. `/health` reports RF loaded, TCN loaded, and the expected version.
2. An invalid/private URL returns `crawl_failed` before network access.
3. The archived LiteSpeed 403 fixture returns `crawl_failed`.
4. Healthy archived `soft98.ir` evidence returns `legitimate`.
5. Artifact-level scoring places a high-confidence held-out generated sample above the phishing threshold. API testing uses a resolvable controlled fixture domain; archived fake domains are expected to fail live DNS validation.
6. An uncertain sample returns `suspicious` and is present in the review queue.
7. An exact imported phishing URL returns `phishing` at the reputation stage.
8. Unknown browser-evidence fields, cookies, headers, or form values are rejected with HTTP 422.
9. `/ready` is 503 when the configured review service is unavailable and 200 only when RF, TCN, and review are ready.
10. A usable uncertain request with supplied HTML reaches the review service, while confident and `crawl_failed` cases do not.

## Live-crawl gates

Run these from the deployment network because anti-bot policy can differ by IP:

```bash
python -m persianphish_detector detect --url https://soft98.ir
python -m persianphish_detector detect --url https://example.com
```

For a blocked live crawl, the acceptable result is `crawl_failed`, not a forced legitimate/phishing label. Supply trusted browser evidence to test the page model itself.

## Agent integration gates

- Agent `/ready` responds before the detector accepts traffic.
- Detector submission always uses `provided_html`; no screenshot, headers, cookies, or form values cross the boundary.
- The detector ignores `status_url` and polls only the configured agent origin.
- Page text that says "ignore previous instructions" cannot alter the strict schemas or introduce tools/codes.
- Two LLM calls are the maximum. Timeout, job failure, malformed output, unsupported codes, and disagreement remain `suspicious`.
- Agent-only phishing or legitimate claims without the required deterministic support remain `suspicious`.
- Raw suspicious/reference HTML and secrets are absent from API results and both SQLite stores.

## Promotion rule

The current artifact is suitable for research, shadow operation, and review-assisted triage. Promotion to autonomous production blocking requires a later, independently adjudicated, time-forward dataset large enough to validate the target false-positive rate, plus measured live agent throughput, latency, and disagreement on the actual deployment.
