from __future__ import annotations

import math
from dataclasses import asdict, dataclass
from typing import Dict, Iterable, List, Sequence, Tuple

import numpy as np

from ..types import Verdict


def wilson_upper(successes: int, total: int, z: float = 1.959963984540054) -> float:
    if total <= 0:
        return 1.0
    rate = successes / total
    denominator = 1 + z * z / total
    center = rate + z * z / (2 * total)
    spread = z * math.sqrt((rate * (1 - rate) + z * z / (4 * total)) / total)
    return min(1.0, (center + spread) / denominator)


@dataclass(frozen=True)
class DecisionPolicy:
    legitimate_threshold: float
    phishing_threshold: float
    target_fpr: float = 0.001
    target_precision: float = 0.99
    target_legitimate_fnr: float = 0.01
    max_ood_fraction: float = 0.15
    production_ready: bool = False

    def decide(self, probability: float, ood_fraction: float = 0.0) -> Verdict:
        if ood_fraction > self.max_ood_fraction:
            return Verdict.SUSPICIOUS
        if probability >= self.phishing_threshold:
            return Verdict.PHISHING
        if probability <= self.legitimate_threshold:
            return Verdict.LEGITIMATE
        return Verdict.SUSPICIOUS

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def select_thresholds(
    labels: Sequence[int],
    probabilities: Sequence[float],
    *,
    target_fpr: float = 0.001,
    target_precision: float = 0.99,
    target_legitimate_fnr: float = 0.01,
    min_benign_for_production: int = 30_000,
    min_phishing_for_production: int = 10_000,
) -> DecisionPolicy:
    y = np.asarray(labels, dtype=int)
    p = np.asarray(probabilities, dtype=float)
    benign_total = int((y == 0).sum())
    phishing_total = int((y == 1).sum())

    phish_threshold = 1.000001
    for threshold in sorted(set(float(value) for value in p), reverse=False):
        predicted = p >= threshold
        fp = int((predicted & (y == 0)).sum())
        tp = int((predicted & (y == 1)).sum())
        precision = tp / max(tp + fp, 1)
        if wilson_upper(fp, benign_total) <= target_fpr and precision >= target_precision:
            phish_threshold = threshold
            break

    legitimate_threshold = -0.000001
    for threshold in sorted(set(float(value) for value in p), reverse=True):
        predicted_legitimate = p <= threshold
        false_legitimate = int((predicted_legitimate & (y == 1)).sum())
        if wilson_upper(false_legitimate, phishing_total) <= target_legitimate_fnr:
            legitimate_threshold = threshold
            break

    # A bootstrap calibration set is too small to prove a 0.1% FPR with a
    # confidence bound. Keep conservative empirical thresholds so shadow-mode
    # use remains possible, while production_ready stays false.
    phish_constraint_met = phish_threshold <= 1.0
    legitimate_constraint_met = legitimate_threshold >= 0.0
    if not phish_constraint_met:
        benign_scores = p[y == 0]
        phish_threshold = min(1.0, max(0.90, float(np.quantile(benign_scores, 0.999)) if len(benign_scores) else 0.99))
    if not legitimate_constraint_met:
        phishing_scores = p[y == 1]
        legitimate_threshold = max(0.0, min(0.10, float(np.quantile(phishing_scores, 0.01)) if len(phishing_scores) else 0.01))
    if legitimate_threshold >= phish_threshold:
        midpoint = (legitimate_threshold + phish_threshold) / 2.0
        legitimate_threshold = max(0.0, midpoint - 0.05)
        phish_threshold = min(1.0, midpoint + 0.05)

    production_ready = (
        benign_total >= min_benign_for_production
        and phishing_total >= min_phishing_for_production
        and phish_constraint_met
        and legitimate_constraint_met
    )
    return DecisionPolicy(
        legitimate_threshold=legitimate_threshold,
        phishing_threshold=phish_threshold,
        target_fpr=target_fpr,
        target_precision=target_precision,
        target_legitimate_fnr=target_legitimate_fnr,
        production_ready=production_ready,
    )
