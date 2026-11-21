"""Evaluate the frozen RF/TCN stage using labeled release test features."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from tempfile import TemporaryDirectory

import numpy as np
import pandas as pd
from sklearn.metrics import average_precision_score, roc_auc_score

from persianphish_detector.config import DetectorConfig
from persianphish_detector.features import FEATURE_COLUMNS
from persianphish_detector.jev_local import LocalJev
from persianphish_detector.models.jev_dataset import isolated_splits
from persianphish_detector.models.policy import wilson_upper
from persianphish_detector.models.tcn import encode_url
from persianphish_detector.orchestrator import Detector
from persianphish_detector.types import Verdict


def evaluate(dataset: Path, artifact_path: Path, local_path: Path | None = None) -> dict:
    frame = pd.read_csv(dataset)
    split = frame.loc[frame["split"] == "test"]
    test = split.loc[
        split["training_eligible"].eq(1)
        & (
            (split["label"].eq(0) & split["label_quality"].eq("verified_legitimate"))
            | (split["label"].eq(1) & split["label_quality"].eq("generated_phishing"))
        )
    ]
    if local_path:
        test = isolated_splits(frame)["test"]
    labels = test["label"].to_numpy(dtype=int)
    if set(labels) != {0, 1}:
        raise ValueError("both trusted test classes are required")
    other = frame.loc[frame["training_eligible"].eq(1) & frame["split"].ne("test")]
    if set(other["group_id"]) & set(test["group_id"]):
        raise ValueError("test group appears in another eligible split")
    local = LocalJev.load(local_path) if local_path else None

    with TemporaryDirectory() as directory:
        tmp = Path(directory)
        detector = Detector(DetectorConfig(
            artifact_path=artifact_path, intel_db_path=tmp / "intel.sqlite",
            review_db_path=tmp / "review.sqlite", result_dir=tmp / "results",
            use_browser=False,
        ))
        artifact, tcn = detector.artifact, detector.tcn
        if artifact is None or tcn is None:
            raise ValueError("both frozen detector artifacts are required")

        rf = artifact.rf_model.predict_proba(test[FEATURE_COLUMNS].to_numpy(dtype=float))[:, 1]
        encoded = np.stack([encode_url(url) for url in test["url"]])
        logits = np.concatenate([
            tcn.session.run(["logit"], {"url_bytes": batch})[0]
            for batch in np.array_split(encoded, max(1, (len(encoded) + 63) // 64))
        ])
        tcn_scores = 1.0 / (1.0 + np.exp(-np.clip(logits.astype(float), -40, 40)))
        combined = np.asarray([
            artifact.combine_scores(float(r), float(t)) for r, t in zip(rf, tcn_scores)
        ])

        routing = {
            label: dict.fromkeys(("legitimate", "phishing", "suspicious"), 0)
            for label in ("legitimate", "phishing")
        }
        local_routes = {
            mode: {label: dict.fromkeys(counts, 0) for label, counts in routing.items()}
            for mode in ("guard_only", "guard_and_auto_flag")
        }
        local_scores = (
            local.model.predict_proba(test[FEATURE_COLUMNS].to_numpy(dtype=float))[:, 1]
            if local else np.zeros(len(test))
        )
        for row, label, r, t, score, local_score in zip(
            test[FEATURE_COLUMNS].to_dict("records"), labels, rf, tcn_scores, combined, local_scores
        ):
            verdict = artifact.policy.decide(float(score), artifact.ood_fraction(row))
            if (
                verdict == Verdict.PHISHING and not artifact.policy.production_ready
                and not detector._bootstrap_phishing_supported(row, float(r), float(t))
            ):
                verdict = Verdict.SUSPICIOUS
            label_name = "phishing" if label else "legitimate"
            routing[label_name][verdict.value] += 1
            if local:
                for mode, counts in local_routes.items():
                    decision, _ = local.decide(
                        verdict, float(local_score), auto_flag=mode == "guard_and_auto_flag"
                    )
                    counts[label_name][decision.value] += 1

        result = {
            "rows": len(test),
            "test_groups": int(test["group_id"].nunique()),
            "models": {
                name: {
                    "roc_auc": float(roc_auc_score(labels, scores)),
                    "average_precision": float(average_precision_score(labels, scores)),
                }
                for name, scores in (("rf", rf), ("tcn", tcn_scores), ("combined", combined))
            },
            "policy": artifact.policy.to_dict(),
            "routing": routing,
            "false_clear_wilson_upper_95": wilson_upper(
                routing["phishing"]["legitimate"], int(labels.sum())
            ),
        }
        if local:
            result["local_jev"] = {
                "roc_auc": float(roc_auc_score(labels, local_scores)),
                "average_precision": float(average_precision_score(labels, local_scores)),
                "review_threshold": local.review_threshold,
                "phishing_threshold": local.phishing_threshold,
                "routing": local_routes,
            }
        return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path("data/processed/realworld_v3_features.csv"))
    parser.add_argument("--artifact", type=Path, default=Path("artifacts/v3/detector_v3_tcn.joblib"))
    parser.add_argument("--local-jev", type=Path)
    args = parser.parse_args()
    print(json.dumps(evaluate(args.dataset, args.artifact, args.local_jev), indent=2))


if __name__ == "__main__":
    main()
