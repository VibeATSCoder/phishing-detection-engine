"""Train and select thresholds for the optional local JEV scorer."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import HistGradientBoostingClassifier

from persianphish_detector.features import FEATURE_COLUMNS
from persianphish_detector.models.jev_dataset import isolated_splits


def train(dataset: Path, output: Path) -> dict:
    frame = pd.read_csv(dataset)
    splits = isolated_splits(frame)
    train_rows, policy_rows = splits["train"], splits["policy"]
    if set(train_rows["label"]) != {0, 1} or set(policy_rows["label"]) != {0, 1}:
        raise ValueError("both classes are required in train and policy")

    model = HistGradientBoostingClassifier(
        max_iter=180, max_leaf_nodes=15, l2_regularization=1.0,
        early_stopping=False, random_state=14,
    )
    model.fit(train_rows[FEATURE_COLUMNS].to_numpy(dtype=float), train_rows["label"])
    scores = model.predict_proba(policy_rows[FEATURE_COLUMNS].to_numpy(dtype=float))[:, 1]
    positives = scores[policy_rows["label"].to_numpy() == 1]
    negatives = np.sort(scores[policy_rows["label"].to_numpy() == 0])
    # Review when a score reaches the lowest phishing score on the policy split.
    review = float(positives.min())
    # With auto flag enabled, accept at most 0.5% false flags on that split.
    allowed = int(len(negatives) * 0.005)
    phishing = float(np.nextafter(negatives[-(allowed + 1)], np.inf))
    if not 0 <= review < phishing <= 1:
        raise ValueError("could not select ordered local JEV thresholds")

    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise FileExistsError(f"refusing to overwrite {output}")
    joblib.dump({
        "kind": "persianphish_jev_local_v1",
        "features": list(FEATURE_COLUMNS),
        "model": model,
        "review_threshold": review,
        "phishing_threshold": phishing,
    }, output, compress=3)
    return {
        "train_rows": len(train_rows),
        "policy_phishing_rows": len(positives),
        "policy_legitimate_rows": len(negatives),
        "review_threshold": review,
        "phishing_threshold": phishing,
        "policy_false_clears": int((positives < review).sum()),
        "policy_phishing_flagged": int((positives >= phishing).sum()),
        "policy_legitimate_flagged": int((negatives >= phishing).sum()),
        "artifact": str(output),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=Path("data/processed/realworld_v3_features.csv"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(train(args.dataset, args.output), indent=2))


if __name__ == "__main__":
    main()
