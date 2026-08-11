from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pandas as pd

from persianphish_detector.features import FEATURE_COLUMNS
from persianphish_detector.models.artifact import load_artifact
from persianphish_detector.models.tcn import ONNXTCNPredictor, TCN_INPUT_CONTRACT


def validate(dataset: Path, artifact_path: Path) -> dict[str, object]:
    frame = pd.read_csv(dataset)
    required = {"sample_id", "url", "label", "label_quality", "group_id", "split", "training_eligible", *FEATURE_COLUMNS}
    missing = sorted(required - set(frame.columns))
    eligible = frame[frame["training_eligible"].astype(int).eq(1)].copy()
    group_cross_split = int((eligible.groupby("group_id")["split"].nunique() > 1).sum())
    duplicate_sample_ids = int(frame["sample_id"].duplicated().sum())
    canonical_urls = frame["url"].astype(str).str.lower().str.rstrip("/")
    duplicate_canonical_urls = int(canonical_urls.duplicated().sum())
    absolute_html_paths = int(frame["html_path"].astype(str).str.match(r"^(?:[A-Za-z]:[\\/]|/)").sum())
    weak_in_training = int(((frame["label_quality"] == "weak_feed") & frame["training_eligible"].astype(bool)).sum())
    trusted_contract = set(eligible["label_quality"].unique()) == {"verified_legitimate", "generated_phishing"}

    artifact = load_artifact(artifact_path)
    tcn_input_contract = (
        artifact.metadata.get("tcn_and_ensemble", {})
        .get("tokenizer", {})
        .get("input_contract")
    )
    tcn_input_contract_matches = tcn_input_contract == TCN_INPUT_CONTRACT
    tcn_path = artifact_path.parent / str(artifact.tcn_model_path or "")
    tcn = ONNXTCNPredictor(tcn_path)
    probes = {
        "known_legitimate": tcn.predict("https://soft98.ir/"),
        "obvious_lookalike": tcn.predict("https://secure-login-paypa1.example/verify"),
    }
    finite_probes = all(np.isfinite(value) and 0 <= value <= 1 for value in probes.values())
    passed = (
        not missing
        and group_cross_split == 0
        and duplicate_sample_ids == 0
        and duplicate_canonical_urls == 0
        and absolute_html_paths == 0
        and weak_in_training == 0
        and trusted_contract
        and tcn_input_contract_matches
        and finite_probes
    )
    return {
        "passed": passed,
        "rows": int(len(frame)),
        "eligible_rows": int(len(eligible)),
        "missing_columns": missing,
        "group_cross_split": group_cross_split,
        "duplicate_sample_ids": duplicate_sample_ids,
        "duplicate_canonical_urls": duplicate_canonical_urls,
        "absolute_html_paths": absolute_html_paths,
        "weak_rows_in_training": weak_in_training,
        "trusted_contract": trusted_contract,
        "model_version": artifact.model_version,
        "policy_production_ready": artifact.policy.production_ready,
        "tcn_input_contract": tcn_input_contract,
        "tcn_input_contract_matches": tcn_input_contract_matches,
        "tcn_path": str(tcn_path),
        "tcn_probes": probes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dataset", default="data/processed/realworld_v3_features.csv")
    parser.add_argument("--artifact", default="artifacts/v3/detector_v3_tcn.joblib")
    parser.add_argument("--report", default="artifacts/v3/release_validation.json")
    args = parser.parse_args()
    report = validate(Path(args.dataset), Path(args.artifact))
    Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
