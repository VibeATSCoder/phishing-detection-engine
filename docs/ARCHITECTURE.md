# Architecture

## Components

| Component | Input | Output | Role |
|---|---|---|---|
| URL safety | User URL | Canonical public URL | Reject malformed URLs, credentials in URLs, and private/reserved destinations. |
| Local intelligence | Canonical URL | Exact scoped match | Phishing URL matches have highest priority; benign host history is corroborative only. |
| HTTP crawler | Public URL | Status, HTML, redirect chain | Fast first observation with manual redirect checks. |
| Chromium crawler | Public URL | Rendered DOM and network hosts | Used for blocked/partial or uncertain pages. |
| Quality gate | Crawl evidence | `ok`, `partial`, `blocked`, or failure state | Prevents error pages from entering feature extraction. |
| RF | 85 URL/HTML/domain features | Calibrated probability + OOD fraction | Main structured detector. |
| URL TCN | Normalized full hostname as UTF-8 bytes, padded to 512 | Calibrated hostname probability | Independent lexical hostname signal; paths and queries are excluded. |
| Policy | RF, TCN, OOD, reputation | Four-state verdict | Uses a wide abstention band and separate thresholds. |
| Agentic review service | Already-observed DOM + optional references | Typed advisory result | Two bounded Gemma/OpenRouter passes with deterministic evidence and reconciliation. |
| Review queue | Suspicious/failure result | Analyst label | Captures feedback without raw HTML, screenshots, cookies, headers, or form values. |

## Decision and trust boundary

The detector is the only public decision API and remains authoritative. Exact phishing intelligence and confident RF/TCN decisions do not call the agent. `crawl_failed` never calls the agent because an unavailable page is not phishing evidence. Only a usable `suspicious` case is submitted to the internal review service using `input_mode=provided_html`, avoiding a second crawl and preserving the exact page observed by the RF.

The standalone service extracts bounded deterministic evidence locally, compares up to three supplied reference candidates, performs an analyst pass and a skeptical verification pass, then returns a strict result. OpenRouter receives sanitized textual/structural signals, never raw HTML, screenshots, cookies, headers, form values, or script bodies. The detector ignores the service-provided status URL and polls only its configured origin.

Agent risk is not blended into the calibrated RF/TCN score. A phishing recommendation requires risk at least 0.80, confidence at least 0.75, and deterministic local risk support. A legitimate recommendation requires risk at most 0.20, confidence at least 0.75, usable evidence, and no deterministic risk. Any timeout, malformed schema, unsupported code, disagreement, or failed job stays `suspicious`.

## Why four states

Binary classification confuses observation failure with phishing. A 403 response says the crawler was denied, not that the site is malicious. `crawl_failed` keeps that distinction explicit. `suspicious` prevents a weak model score or agent disagreement from becoming a false accusation.

Because the current policy is a research bootstrap, a high RF score alone is not enough for an autonomous phishing verdict. The fast path also needs high RF/TCN agreement or a concrete domain/credential mismatch; otherwise the review tier receives the case.

## Security controls

- Every initial URL, redirect, supplied final URL, and new browser request host is resolved and checked against private, loopback, link-local, multicast, and reserved ranges.
- HTTP and browser redirect validation is manual; browser contexts are isolated and downloads are disabled.
- Unknown input fields are rejected. Reference HTML is limited to 2 MB each and 5 MB total; suspicious HTML is limited to 5 MB. The detector rejects declared or streamed request bodies above 14 MB, and the internal review API above 11 MB, before JSON/form parsing.
- Error/challenge responses never reach the agent as healthy evidence.
- The detector-to-agent client disables proxy inheritance and redirects, validates bounded response schemas, and never follows a returned callback URL.
- Raw suspicious/reference HTML is never persisted by either service. Stored review evidence is sanitized.
- The review service has no browsing or code-execution tools and cannot submit forms, follow QR destinations, download files, or interact with authentication flows.
- Exact URL indicators do not blacklist unrelated paths. Benign history remains host-scoped corroboration and cannot override exact phishing intelligence.

## Latency tiers

| Tier | Work | Outcome |
|---|---|---|
| Fast | HTTP + RF + ONNX TCN | Confident model-policy result |
| Rendered | Chromium + RF + TCN | Dynamic or uncertain page evidence |
| Agent | Existing DOM + two bounded OpenRouter calls | Advisory reconciliation for usable uncertainty |
| Failure | Quality state only | `crawl_failed`; no agent inference |
