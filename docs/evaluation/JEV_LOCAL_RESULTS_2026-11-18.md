# Local JEV results, 2026-11-18

The local JEV scorer uses the detector's existing structural features and a
separate gradient-boosted classifier. When configured, it can intercept a fast
clearance and send the page to review. Direct phishing verdicts require the
separate auto-flag option. Local JEV scores remain separate from the frozen
RF/TCN score and the optional external provider's scores.

## Split and threshold selection

Training used 9,347 eligible train rows. The policy split supplied 590 generated
phishing and 841 verified legitimate rows for threshold selection. Source group,
actual URL registrable domain and exact feature-vector overlap are excluded across
splits. Weak-feed examples were excluded.

The review cutoff of 0.001607 was the lowest phishing score in the policy split.
The auto-flag cutoff of 0.779868 was selected at a maximum empirical false flag
rate of 0.5% on that split. It flagged 538/590 phishing and 4/841 legitimate
examples there. Both cutoffs were selected before the isolated test replay.

## Held-out release feature replay

The isolated test set has 654 generated phishing and 934 verified legitimate
rows. Of the original 1,780 test rows, 192 overlapped an earlier split by actual
registrable domain or exact feature vector and were excluded from this comparison.

| Mode | Phishing flagged | Phishing deferred | Phishing cleared | Legitimate flagged | Legitimate deferred |
| --- | ---: | ---: | ---: | ---: | ---: |
| Frozen RF/TCN | 449/654 (68.65%) | 202 | 3 | 1/934 (0.11%) | 461 |
| RF/TCN + local JEV guard | 449/654 (68.65%) | 205 | **0** | 1/934 (0.11%) | 696 |
| RF/TCN + guard and auto-flag | **605/654 (92.51%)** | 49 | **0** | 7/934 (0.75%) | 690 |

The guard intercepted all three early phishing clearances. It sent 235 more
legitimate cases to review. The auto-flag experiment issued 156 additional
phishing verdicts and six additional false alarms. The 49 deferred positives
still need a downstream verdict.

## Archived HTML smoke replay

The detector re-extracted features from 32 phishing and 32 legitimate archives
sampled from the same isolated split with seed 84. The replay used captured
browser evidence, simulated DNS and missing live domain facts. It ran locally
without an external screener or final reviewer.

| Mode | Phishing flagged | Phishing deferred | Phishing cleared | Legitimate flagged | Legitimate deferred |
| --- | ---: | ---: | ---: | ---: | ---: |
| Frozen RF/TCN | 20/32 | 12 | 0 | 1/32 | 16 |
| RF/TCN + local JEV guard | 20/32 | 12 | 0 | 1/32 | 21 |
| RF/TCN + guard and auto-flag | **29/32** | 3 | 0 | 1/32 | 21 |

## Verification and activation

All 242 detector tests and detector release validation passed. The extension
passed six focused presentation cases plus seven existing presentation checks.
The presentation changes preserve backend warnings at low earlier scores
and stop showing a safe check for a backend crawl failure. The extension's
model parity passes with the refreshed integration assertions. Its separate
training-source audit still requires the original dataset checksum.

Use the artifact at `artifacts/v3/jev_local_isolated.joblib` with
`PPD_JEV_LOCAL_MODEL_PATH`. Enable it with `PPD_JEV_ENABLED=1` and keep
`PPD_JEV_LOCAL_AUTO_FLAG=0` for routing-only use. The evaluation commands are
in the detector's `deploy/INTEGRATED.md`.

Observed detection and clearance rates apply to this generated benchmark.
Live-provider and independent real-world recall remain unmeasured.
