from __future__ import annotations

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Mapping, Tuple

import numpy as np
import pandas as pd
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import RandomForestClassifier
from sklearn.impute import SimpleImputer
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.pipeline import Pipeline

from ..features import FEATURE_COLUMNS
from .artifact import DetectorArtifact
from .policy import select_thresholds


RANDOM_STATE = 20260717
RF_CANDIDATES: Dict[str, Dict[str, Any]] = {
    "balanced_general": {
        "max_depth": 24,
        "min_samples_split": 8,
        "min_samples_leaf": 4,
        "max_features": 0.4,
        "max_samples": 0.9,
        "class_weight": {0: 1.35, 1: 1.0},
    },
    "low_variance": {
        "max_depth": 18,
        "min_samples_split": 12,
        "min_samples_leaf": 6,
        "max_features": 0.3,
        "max_samples": 0.9,
        "class_weight": {0: 1.5, 1: 1.0},
    },
    "fine_grained": {
        "max_depth": 30,
        "min_samples_split": 5,
        "min_samples_leaf": 2,
        "max_features": "sqrt",
        "max_samples": 0.9,
        "class_weight": {0: 1.35, 1: 1.0},
    },
    "false_positive_averse": {
        "max_depth": 24,
        "min_samples_split": 10,
        "min_samples_leaf": 5,
        "max_features": 0.35,
        "max_samples": 0.85,
        "class_weight": {0: 2.0, 1: 1.0},
    },
}


def expected_calibration_error(labels: np.ndarray, probabilities: np.ndarray, bins: int = 15) -> float:
    edges = np.linspace(0.0, 1.0, bins + 1)
    result = 0.0
    for left, right in zip(edges[:-1], edges[1:]):
        mask = (probabilities >= left) & (probabilities < right if right < 1 else probabilities <= right)
        if mask.any():
            result += mask.mean() * abs(float(labels[mask].mean()) - float(probabilities[mask].mean()))
    return float(result)


def metrics(labels: np.ndarray, probabilities: np.ndarray, threshold: float = 0.5) -> Dict[str, float | int]:
    predictions = (probabilities >= threshold).astype(int)
    benign = labels == 0
    false_positives = int((predictions.astype(bool) & benign).sum())
    benign_rows = int(benign.sum())
    return {
        "rows": int(len(labels)),
        "positive_rows": int(labels.sum()),
        "threshold": float(threshold),
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1": float(f1_score(labels, predictions, zero_division=0)),
        "false_positives": false_positives,
        "false_positive_rate": false_positives / benign_rows if benign_rows else 0.0,
        "roc_auc": float(roc_auc_score(labels, probabilities)) if len(set(labels)) == 2 else 0.0,
        "pr_auc": float(average_precision_score(labels, probabilities)) if len(set(labels)) == 2 else 0.0,
        "brier": float(brier_score_loss(labels, probabilities)),
        "ece": expected_calibration_error(labels, probabilities),
    }


def zero_observed_fp_metrics(labels: np.ndarray, probabilities: np.ndarray) -> Dict[str, float | int]:
    benign_scores = probabilities[labels == 0]
    threshold = min(1.0, float(np.nextafter(benign_scores.max(), 1.0))) if len(benign_scores) else 1.0
    return metrics(labels, probabilities, threshold)


def frame_xy(frame: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    missing = [column for column in ["label", *FEATURE_COLUMNS] if column not in frame.columns]
    if missing:
        raise ValueError(f"training dataset missing columns: {missing[:10]}")
    return frame[FEATURE_COLUMNS].astype(float).to_numpy(), frame["label"].astype(int).to_numpy()


def _base_model(params: Mapping[str, Any], n_jobs: int, n_estimators: int) -> Pipeline:
    rf = RandomForestClassifier(
        n_estimators=n_estimators,
        criterion="log_loss",
        random_state=RANDOM_STATE,
        n_jobs=n_jobs,
        **dict(params),
    )
    return Pipeline([("imputer", SimpleImputer(strategy="median", add_indicator=True)), ("rf", rf)])


def _candidate_key(report: Mapping[str, Any]) -> Tuple[float, float, float, float]:
    zero_fp = report["policy_zero_observed_fp"]
    standard = report["policy_at_0_5"]
    return (
        float(zero_fp["recall"]),
        float(standard["pr_auc"]),
        float(standard["roc_auc"]),
        -float(standard["brier"]),
    )


def _stratified_metrics(frame: pd.DataFrame, probabilities: np.ndarray, threshold: float) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    scored = frame.copy()
    scored["probability"] = probabilities
    for column in ("label_quality", "html_technique_id", "url_technique_id"):
        if column not in scored:
            continue
        groups: Dict[str, Any] = {}
        for value, subset in scored.groupby(column, dropna=False):
            if len(subset) < 2:
                continue
            labels = subset["label"].astype(int).to_numpy()
            probs = subset["probability"].astype(float).to_numpy()
            predictions = (probs >= threshold).astype(int)
            groups[str(value or "none")] = {
                "rows": int(len(subset)),
                "mean_probability": float(probs.mean()),
                "predicted_phishing_rate": float(predictions.mean()),
                "recall": float(recall_score(labels, predictions, zero_division=0)) if labels.sum() else None,
            }
        result[column] = groups
    return result


def _weak_stress_metrics(frame: pd.DataFrame, probabilities: np.ndarray, threshold: float) -> Dict[str, Any]:
    if frame.empty:
        return {"rows": 0, "interpretation": "No weak-label rows were available."}
    return {
        "rows": int(len(frame)),
        "score_quantiles": {
            str(q): float(np.quantile(probabilities, q)) for q in (0.0, 0.1, 0.25, 0.5, 0.75, 0.9, 1.0)
        },
        "predicted_phishing_rate_at_policy_threshold": float((probabilities >= threshold).mean()),
        "interpretation": (
            "Stress diagnostic only. These captures came from broad domain blocklists and are not "
            "verified phishing ground truth, so precision/recall are intentionally not reported."
        ),
    }


def train(
    dataset_path: Path,
    output_path: Path,
    n_jobs: int = 1,
    search_estimators: int = 700,
) -> Dict[str, Any]:
    frame = pd.read_csv(dataset_path)
    if "training_eligible" in frame:
        eligible = frame[frame["training_eligible"].astype(int).eq(1)].copy()
    else:
        eligible = frame[~frame["split"].astype(str).eq("weak_stress")].copy()
    required_splits = {"train", "calibration", "policy", "test"}
    if "split" not in eligible or not required_splits.issubset(set(eligible["split"].astype(str))):
        raise ValueError(f"dataset must contain eligible split values {sorted(required_splits)}")
    split_frames = {name: eligible[eligible["split"] == name].reset_index(drop=True) for name in required_splits}
    weak_frame = frame[frame["split"].astype(str).eq("weak_stress")].reset_index(drop=True)

    X_train, y_train = frame_xy(split_frames["train"])
    X_cal, y_cal = frame_xy(split_frames["calibration"])
    X_policy, y_policy = frame_xy(split_frames["policy"])
    candidates: Dict[str, Dict[str, Any]] = {}
    candidate_objects: Dict[str, Tuple[Any, Pipeline]] = {}
    for candidate_name, params in RF_CANDIDATES.items():
        base = _base_model(params, n_jobs=n_jobs, n_estimators=search_estimators)
        base.fit(X_train, y_train)
        for method in ("sigmoid", "isotonic"):
            calibrated = CalibratedClassifierCV(base, method=method, cv="prefit")
            calibrated.fit(X_cal, y_cal)
            policy_prob = calibrated.predict_proba(X_policy)[:, 1]
            name = f"{candidate_name}__{method}"
            candidate_report = {
                "forest": candidate_name,
                "calibration": method,
                "rf_params": {**params, "n_estimators": search_estimators, "n_jobs": n_jobs},
                "policy_at_0_5": metrics(y_policy, policy_prob),
                "policy_zero_observed_fp": zero_observed_fp_metrics(y_policy, policy_prob),
            }
            candidates[name] = candidate_report
            candidate_objects[name] = (calibrated, base)

    selected_name = max(candidates, key=lambda name: _candidate_key(candidates[name]))
    model, selected_base = candidate_objects[selected_name]
    selected_report = candidates[selected_name]
    policy_prob = model.predict_proba(X_policy)[:, 1]
    policy = select_thresholds(y_policy, policy_prob)

    quantiles = split_frames["train"][FEATURE_COLUMNS].astype(float).quantile([0.005, 0.995])
    ranges = {
        column: (float(quantiles.loc[0.005, column]), float(quantiles.loc[0.995, column]))
        for column in FEATURE_COLUMNS
    }
    X_test, y_test = frame_xy(split_frames["test"])
    test_prob = model.predict_proba(X_test)[:, 1]
    policy_threshold = min(policy.phishing_threshold, 1.0)
    report: Dict[str, Any] = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_path": str(dataset_path),
        "feature_count": len(FEATURE_COLUMNS),
        "training_contract": {
            "trusted_negative": "verified legitimate archive",
            "trusted_positive": "validated PersianPhish generated samples",
            "group_isolation": "registrable source domain is assigned to exactly one split",
            "weak_feed_usage": "excluded from fitting, calibration, policy selection, and formal test metrics",
        },
        "selected_candidate": selected_name,
        "candidate_selection_order": [
            "policy recall with zero observed false positives",
            "policy PR AUC",
            "policy ROC AUC",
            "policy Brier score",
        ],
        "candidates": candidates,
        "policy": policy.to_dict(),
        "splits": {
            name: {
                "rows": int(len(value)),
                "labels": {str(k): int(v) for k, v in value["label"].value_counts().to_dict().items()},
            }
            for name, value in split_frames.items()
        },
        "test_at_0_5": metrics(y_test, test_prob),
        "test_at_policy_threshold": metrics(y_test, test_prob, threshold=policy_threshold),
        "test_zero_observed_fp": zero_observed_fp_metrics(y_test, test_prob),
        "test_strata_at_policy_threshold": _stratified_metrics(split_frames["test"], test_prob, policy_threshold),
    }
    if not weak_frame.empty:
        X_weak, _ = frame_xy(weak_frame)
        weak_prob = model.predict_proba(X_weak)[:, 1]
        report["weak_feed_stress"] = _weak_stress_metrics(weak_frame, weak_prob, policy_threshold)
    else:
        weak_prob = np.asarray([], dtype=float)
        report["weak_feed_stress"] = _weak_stress_metrics(weak_frame, weak_prob, policy_threshold)

    artifact = DetectorArtifact(
        rf_model=model,
        feature_columns=FEATURE_COLUMNS,
        policy=policy,
        model_version="v3-realworld-" + datetime.now(timezone.utc).strftime("%Y%m%d"),
        feature_ranges=ranges,
        metadata=report,
    )
    artifact.save(output_path)
    output_path.with_name(output_path.stem + "_metrics.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    importance = selected_base.named_steps["rf"].feature_importances_
    pd.DataFrame({"feature": FEATURE_COLUMNS, "importance": importance}).sort_values(
        "importance", ascending=False
    ).to_csv(output_path.with_name(output_path.stem + "_feature_importance.csv"), index=False)

    predictions = split_frames["test"][[
        column for column in (
            "sample_id", "url", "label", "label_quality", "group_id", "url_technique_id", "html_technique_id"
        ) if column in split_frames["test"]
    ]].copy()
    predictions["probability"] = test_prob
    predictions["prediction_at_0_5"] = (test_prob >= 0.5).astype(int)
    predictions["prediction_at_policy_threshold"] = (test_prob >= policy_threshold).astype(int)
    predictions.to_csv(output_path.with_name(output_path.stem + "_test_predictions.csv"), index=False)
    if not weak_frame.empty:
        weak_predictions = weak_frame[[
            column for column in ("sample_id", "url", "label_quality", "group_id", "source_type") if column in weak_frame
        ]].copy()
        weak_predictions["probability"] = weak_prob
        weak_predictions.to_csv(output_path.with_name(output_path.stem + "_weak_stress_predictions.csv"), index=False)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Train, tune, and calibrate the real-world RF artifact")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--output", default="artifacts/v3/detector_v3.joblib")
    parser.add_argument("--n-jobs", type=int, default=1)
    parser.add_argument("--search-estimators", type=int, default=700)
    args = parser.parse_args()
    report = train(
        Path(args.dataset),
        Path(args.output),
        n_jobs=args.n_jobs,
        search_estimators=args.search_estimators,
    )
    print(json.dumps({
        "selected_candidate": report["selected_candidate"],
        "test_at_0_5": report["test_at_0_5"],
        "test_at_policy_threshold": report["test_at_policy_threshold"],
        "production_ready": report["policy"]["production_ready"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
