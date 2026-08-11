from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

import joblib
import numpy as np

from ..features import FEATURE_COLUMNS, feature_vector
from .policy import DecisionPolicy


@dataclass
class DetectorArtifact:
    rf_model: Any
    feature_columns: Sequence[str]
    policy: DecisionPolicy
    model_version: str
    feature_ranges: Dict[str, Tuple[float, float]]
    metadata: Dict[str, Any]
    tcn_model_path: Optional[str] = None
    score_combiner: Optional[Dict[str, float]] = None

    def predict_rf(self, features: Mapping[str, float]) -> Tuple[float, float]:
        missing = [column for column in self.feature_columns if column not in features]
        if missing:
            raise ValueError(f"missing model features: {missing[:10]}")
        row = np.asarray([[float(features[column]) for column in self.feature_columns]], dtype=float)
        probability = float(self.rf_model.predict_proba(row)[0, 1])
        ood = self.ood_fraction(features)
        return probability, ood

    def ood_fraction(self, features: Mapping[str, float]) -> float:
        if not self.feature_ranges:
            return 0.0
        outside = 0
        checked = 0
        for name, bounds in self.feature_ranges.items():
            if name not in features:
                continue
            low, high = bounds
            value = float(features[name])
            checked += 1
            outside += int(value < low or value > high)
        return outside / checked if checked else 0.0

    def combine_scores(self, rf_probability: Optional[float], tcn_probability: Optional[float]) -> float:
        if rf_probability is None and tcn_probability is None:
            return 0.5
        if rf_probability is None:
            return float(tcn_probability)
        if tcn_probability is None or not self.score_combiner:
            return float(rf_probability)
        weight = float(self.score_combiner.get("tcn_weight", 0.0))
        blend = (1.0 - weight) * float(rf_probability) + weight * float(tcn_probability)
        blend = float(np.clip(blend, 1e-6, 1.0 - 1e-6))
        logit = np.log(blend / (1.0 - blend))
        calibrated_logit = (
            float(self.score_combiner.get("slope", 1.0)) * logit
            + float(self.score_combiner.get("intercept", 0.0))
        )
        return float(1.0 / (1.0 + np.exp(-calibrated_logit)))

    def to_bundle(self) -> Dict[str, Any]:
        return {
            "artifact_type": "persianphish_realworld_detector",
            "artifact_version": 2,
            "rf_model": self.rf_model,
            "feature_columns": list(self.feature_columns),
            "policy": self.policy.to_dict(),
            "model_version": self.model_version,
            "feature_ranges": self.feature_ranges,
            "metadata": self.metadata,
            "tcn_model_path": self.tcn_model_path,
            "score_combiner": self.score_combiner,
        }

    def save(self, path: Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        joblib.dump(self.to_bundle(), path, compress=3)


def load_artifact(path: Path) -> DetectorArtifact:
    bundle = joblib.load(path)
    if bundle.get("artifact_type") != "persianphish_realworld_detector" or bundle.get("artifact_version") != 2:
        raise ValueError("not_a_v2_detector_artifact")
    feature_columns = list(bundle["feature_columns"])
    if feature_columns != FEATURE_COLUMNS:
        raise ValueError("artifact_feature_schema_mismatch")
    policy = DecisionPolicy(**bundle["policy"])
    ranges = {str(key): (float(value[0]), float(value[1])) for key, value in bundle.get("feature_ranges", {}).items()}
    return DetectorArtifact(
        rf_model=bundle["rf_model"],
        feature_columns=feature_columns,
        policy=policy,
        model_version=str(bundle.get("model_version", "v2")),
        feature_ranges=ranges,
        metadata=dict(bundle.get("metadata", {})),
        tcn_model_path=bundle.get("tcn_model_path"),
        score_combiner=bundle.get("score_combiner"),
    )
