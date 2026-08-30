#!/usr/bin/env python3
"""Pin the released detector's benchmark numbers and data-hygiene invariants.

Why this exists
---------------
The accuracy figures for this detector lived only in prose. Nothing recomputed
them, so nothing noticed when they drifted from the artifacts: the README quoted
"0.9987 precision, 0.9207 recall, and 1 false positive", while the shipped
``detector_v3_metrics.json`` and ``detector_v3_test_predictions.csv`` both give
0.99738 / 0.90059 with **two** false positives. The figures were not reproducible
from anything in the repository.

This recomputes the headline metrics from the shipped predictions, checks them
against the recorded metrics, and fails on drift. Running it in CI means a
change to the policy, the thresholds, or the artifacts can no longer alter the
published numbers silently.

It is deliberately offline and fast: it reads shipped files and does no
inference, so it can gate every push.

    python scripts/check_release_metrics.py
"""

from __future__ import annotations

import csv
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ARTIFACTS = ROOT / "artifacts" / "v3"

# Recomputed from artifacts/v3/detector_v3_test_predictions.csv on the released
# model. Update these ONLY together with a regenerated artifact, and say so in
# the commit message: they are the numbers the project claims in public.
EXPECTED = {
    "rows": 1780,
    "positive_rows": 845,
    "negative_rows": 935,
    "precision": 0.9973787680209698,
    "recall": 0.9005917159763314,
    "false_positives": 2,
}
TOLERANCE = 1e-6

failures: list[str] = []


def check(condition: bool, message: str) -> None:
    print(f"  {'ok  ' if condition else 'FAIL'}  {message}")
    if not condition:
        failures.append(message)


def close(actual: float, expected: float) -> bool:
    return abs(actual - expected) <= TOLERANCE


print("recomputing the benchmark from shipped predictions")
rows = list(csv.DictReader((ARTIFACTS / "detector_v3_test_predictions.csv").open()))
positives = [r for r in rows if r["label"] == "1"]
negatives = [r for r in rows if r["label"] == "0"]

true_positive = sum(1 for r in positives if r["prediction_at_policy_threshold"] == "1")
false_positive = sum(1 for r in negatives if r["prediction_at_policy_threshold"] == "1")
false_negative = len(positives) - true_positive
precision = true_positive / (true_positive + false_positive)
recall = true_positive / (true_positive + false_negative)

check(len(rows) == EXPECTED["rows"], f"test set has {EXPECTED['rows']} rows (got {len(rows)})")
check(len(positives) == EXPECTED["positive_rows"], f"{EXPECTED['positive_rows']} phishing rows (got {len(positives)})")
check(len(negatives) == EXPECTED["negative_rows"], f"{EXPECTED['negative_rows']} legitimate rows (got {len(negatives)})")
check(close(precision, EXPECTED["precision"]), f"precision {EXPECTED['precision']:.6f} (got {precision:.6f})")
check(close(recall, EXPECTED["recall"]), f"recall {EXPECTED['recall']:.6f} (got {recall:.6f})")
check(false_positive == EXPECTED["false_positives"], f"{EXPECTED['false_positives']} false positives (got {false_positive})")

print("\nagreeing with the recorded metrics file")
metrics = json.loads((ARTIFACTS / "detector_v3_metrics.json").read_text(encoding="utf-8"))
recorded = metrics["test_at_policy_threshold"]
check(close(recorded["precision"], precision), "metrics.json precision matches the predictions")
check(close(recorded["recall"], recall), "metrics.json recall matches the predictions")
check(recorded["false_positives"] == false_positive, "metrics.json false positives match the predictions")

print("\ndata-hygiene invariants from release validation")
validation = json.loads((ARTIFACTS / "release_validation.json").read_text(encoding="utf-8"))
check(validation["passed"] is True, "release validation passed")
# These three are the properties that make the benchmark meaningful at all. A
# group spanning splits or a weak-feed row in training would inflate the score
# without any code changing.
check(validation["group_cross_split"] == 0, "no registrable-domain group spans splits")
check(validation["weak_rows_in_training"] == 0, "no weak_feed rows entered training")
check(validation["duplicate_canonical_urls"] == 0, "no duplicate canonical URLs")
check(validation["tcn_input_contract_matches"] is True, "TCN input contract matches the artifact")

print("\nthe artifact's own honesty flag")
# Not a failure. It is surfaced so that flipping it is a visible, deliberate act
# rather than something noticed later.
ready = validation.get("policy_production_ready")
print(f"  note  policy_production_ready = {ready}")
if ready:
    print("        this artifact now claims production readiness; confirm the")
    print("        benign corpus is large enough to support the FPR target.")

print(f"\n{len(failures)} failure(s)")
for failure in failures:
    print(f"  - {failure}")
sys.exit(1 if failures else 0)
