"""Optional offline JEV scoring from the detector's versioned feature schema."""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

import joblib

from .features import FEATURE_COLUMNS, feature_vector
from .types import Verdict


@dataclass(frozen=True)
class LocalJev:
    model: Any
    review_threshold: float
    phishing_threshold: float

    @classmethod
    def load(cls, path: Path) -> LocalJev:
        bundle = joblib.load(path)
        if bundle.get("kind") != "persianphish_jev_local_v1":
            raise ValueError("invalid_local_jev_artifact")
        if bundle.get("features") != list(FEATURE_COLUMNS):
            raise ValueError("invalid_local_jev_feature_schema")
        model = bundle["model"]
        if list(model.classes_) != [0, 1] or model.n_features_in_ != len(FEATURE_COLUMNS):
            raise ValueError("invalid_local_jev_model_schema")
        review = float(bundle["review_threshold"])
        phishing = float(bundle["phishing_threshold"])
        if not 0 <= review < phishing <= 1:
            raise ValueError("invalid_local_jev_thresholds")
        return cls(model, review, phishing)

    def score(self, features: Mapping[str, float]) -> float:
        risk = float(self.model.predict_proba([feature_vector(features)])[0, 1])
        if not math.isfinite(risk) or not 0 <= risk <= 1:
            raise ValueError("invalid_local_jev_score")
        return risk

    def decide(
        self, baseline: Verdict, risk: float | None, *, auto_flag: bool
    ) -> tuple[Verdict, str]:
        if baseline == Verdict.PHISHING:
            return baseline, "jev_local_confirmed_upstream"
        if risk is None:
            return Verdict.SUSPICIOUS, "jev_local_unavailable"
        if auto_flag and risk >= self.phishing_threshold:
            return Verdict.PHISHING, "jev_local_phishing_threshold"
        if risk >= self.review_threshold:
            return Verdict.SUSPICIOUS, "jev_local_review_threshold"
        return baseline, "jev_local_below_review_threshold"
