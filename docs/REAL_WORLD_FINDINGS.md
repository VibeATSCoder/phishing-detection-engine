# Real-World Failure Analysis

## Why the earlier model flagged `soft98.ir`

The failure was caused by several independent problems that reinforced each other.

| Problem | Evidence | V3 correction |
|---|---|---|
| HTTP error treated as page | The crawler saved a 1,295-byte LiteSpeed 403 response as `ok`. | Status and challenge-page quality gate runs before feature extraction. |
| Contradictory labels | Healthy `soft98.ir` and `linkdoni.soft98.ir` captures existed in both legitimate and "real phishing" rows. | Broad blocklist captures are weak labels; conflicts are quarantined and all weak labels are excluded from formal training/evaluation. |
| Synthetic artifacts dominated | URL digit ratio, token count, and hyphens dominated the old forest. | Domain-isolated generated evaluation, regularized RF search, conservative thresholds, TCN capped by ensemble calibration, and an abstention state. |
| One fixed threshold | A probability above 0.5 became phishing even without calibrated real-world evidence. | Separate legitimate/phishing thresholds with a wide `suspicious` interval and OOD gate. |
| Missing crawl state | Failed observations still received a content label. | `crawl_failed` is a first-class output. |
| Non-reproducible TCN | Tokenizer/schema and checkpoint assumptions lived in notebook state. | Fixed UTF-8 byte encoding, versioned checkpoint, ONNX graph, calibration, and reload tests. |

## What the weak archive actually means

AdGuard Home and Dangerous Domains captures show that a domain appeared in a broad defensive list at collection time. That can indicate phishing, malware, unwanted software, historical compromise, or a stale/incorrect entry. It is not enough to assert that the archived page itself is phishing. V3 preserves these rows for stress analysis but does not calculate accuracy, precision, or recall from them.

## What is now proven

- The trusted model table has unique canonical URLs and source-domain-isolated splits.
- Healthy archived `soft98.ir` is classified as legitimate by the final pipeline.
- Its known LiteSpeed 403 fixture becomes `crawl_failed`.
- RF and TCN artifacts reload and produce bounded probabilities.
- Held-out generated techniques are detected with a conservative no-observed-false-positive threshold on the current blind test.
- Weak-feed rows cannot enter model fitting through the default builder/trainer.

## What is not yet proven

- A 0.1% open-world false-positive rate. The benign test set is too small for that statistical claim.
- General recall against all active internet phishing. Formal positives are generated techniques, not an independently adjudicated time-forward feed.
- Live OpenRouter reviewer latency and throughput from the target deployment network. The deterministic Docker smoke test validates the integration contract but does not measure external-model performance.

For that reason the artifact records `production_ready=false`. The appropriate current use is research, shadow evaluation, and review-assisted triage.
