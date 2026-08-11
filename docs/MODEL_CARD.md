# Model Card

## Intended use

V3 is a conservative triage detector for Persian and multilingual websites. It is designed to identify high-confidence generated phishing, return uncertainty explicitly, and route difficult pages to local review. It is not a replacement for browser isolation, endpoint controls, or analyst confirmation.

## Models

| Model | Contract | Role |
|---|---|---|
| Random Forest | 700 trees, 85 fixed numeric features, sigmoid calibration | Primary URL + HTML detector |
| URL TCN | Normalized full-hostname UTF-8 bytes, length 512, vocabulary 257, four residual dilated blocks, ONNX | Independent lexical hostname evidence; paths and queries are excluded |
| Ensemble | 80% RF + 20% TCN followed by sigmoid calibration | Final fast score |
| Agentic reviewer | LangGraph, two strict Gemma/OpenRouter passes, deterministic reconciliation | Advisory review of usable uncertain cases; no raw HTML is sent to the LLM |

The ensemble weight was selected on the policy split. The TCN was not allowed to dominate the stronger HTML-aware RF.

## Blind generated-technique test

| Model/threshold | Precision | Recall | F1 | ROC AUC | False positives / 935 |
|---|---:|---:|---:|---:|---:|
| RF at 0.5 | 0.9769 | 0.9503 | 0.9634 | 0.9933 | 19 |
| RF conservative threshold 0.9461 | 0.9974 | 0.9006 | 0.9465 | 0.9933 | 2 |
| TCN at 0.5 | 0.9884 | 0.7077 | 0.8248 | 0.8593 | 7 |
| Ensemble conservative threshold 0.9285 | 0.9987 | 0.9207 | 0.9581 | 0.9935 | 1 |

The test positives are held-out generated phishing techniques. These numbers do not estimate precision or recall against arbitrary internet traffic.

## Decision policy

- `risk <= 0.026179`: eligible for `legitimate`, unless OOD or deterministic evidence disagrees.
- `risk >= 0.928477`: eligible for `phishing`.
- Between thresholds: `suspicious` and optionally agent-reviewed.
- Unusable crawl: `crawl_failed` regardless of model appearance.
- OOD fraction above 0.15: `suspicious`.
- While `production_ready=false`, a model-based phishing verdict also requires RF/TCN agreement above the phishing threshold or concrete redirect, confusable-domain, or credential-form mismatch evidence. Otherwise it is downgraded to `suspicious` for review.

The policy stores a target FPR of 0.1% and target precision of 99%, but `production_ready=false`. A test with only 935 benign samples cannot establish the FPR target with a useful confidence bound.

## Observed regression case

With healthy archived browser evidence for `soft98.ir`, V3 returns `legitimate` with verified benign-history corroboration. The known LiteSpeed 403 body returns `crawl_failed`, not phishing. This is a regression expectation, not a claim about a live crawl at a particular time.

## Risks

- Attackers can adapt to lexical and DOM features.
- An LLM can hallucinate or be influenced by page text; strict schemas, skeptical verification, local evidence, and deterministic reconciliation limit its authority but do not eliminate error.
- Reputation feeds can contain stale or broad indicators.
- Browser rendering increases attack surface and must run in an isolated container/host.
- Calibration will drift as site design and phishing techniques change.

Monitor verdict rates, crawl failure causes, OOD rate, review disagreement, and time-forward false positives. Recalibrate before changing thresholds.
