import numpy as np
import pytest

from persianphish_detector.models.artifact import DetectorArtifact
from persianphish_detector.models.policy import DecisionPolicy, select_thresholds, wilson_upper
from persianphish_detector.types import Verdict


def test_policy_has_abstention_band_and_ood_gate():
    policy = DecisionPolicy(legitimate_threshold=0.1, phishing_threshold=0.9)
    assert policy.decide(0.05) == Verdict.LEGITIMATE
    assert policy.decide(0.95) == Verdict.PHISHING
    assert policy.decide(0.5) == Verdict.SUSPICIOUS
    assert policy.decide(0.01, ood_fraction=0.5) == Verdict.SUSPICIOUS


def test_small_calibration_set_is_not_marked_production_ready():
    labels = np.array([0] * 100 + [1] * 100)
    probabilities = np.array([0.01] * 100 + [0.99] * 100)
    policy = select_thresholds(labels, probabilities)
    assert not policy.production_ready


def test_wilson_upper_is_conservative():
    assert wilson_upper(0, 100) > 0
    assert wilson_upper(1, 1000) > 0.001


def test_artifact_combiner_matches_saved_blend_contract():
    artifact = DetectorArtifact(
        rf_model=None,
        feature_columns=[],
        policy=None,  # type: ignore[arg-type]
        model_version="test",
        feature_ranges={},
        metadata={},
        score_combiner={"tcn_weight": 0.25, "slope": 1.0, "intercept": 0.0},
    )
    assert artifact.combine_scores(0.8, 0.4) == pytest.approx(0.7)
    assert artifact.combine_scores(0.8, None) == pytest.approx(0.8)
