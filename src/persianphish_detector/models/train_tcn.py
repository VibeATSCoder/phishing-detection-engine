from __future__ import annotations

import argparse
import copy
import json
import random
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, Tuple

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score

from ..features import FEATURE_COLUMNS
from .artifact import DetectorArtifact, load_artifact
from .policy import select_thresholds
from .tcn import (
    MAX_URL_BYTES,
    TCN_INPUT_CONTRACT,
    ONNXTCNPredictor,
    URLTCN,
    encode_url,
    export_onnx,
)
from .train_rf import metrics, zero_observed_fp_metrics


SEED = 20260717


def _require_torch():
    try:
        import torch
        from torch import nn
        from torch.utils.data import DataLoader, TensorDataset
    except ImportError as exc:  # pragma: no cover - dependency guard
        raise RuntimeError("Install requirements-tcn.txt before training the URL TCN") from exc
    if URLTCN is None:
        raise RuntimeError("URLTCN was unavailable when persianphish_detector.models.tcn was imported")
    return torch, nn, DataLoader, TensorDataset


def _encode_frame(frame: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
    urls = frame["url"].astype(str).tolist()
    encoded = np.stack([encode_url(url) for url in urls]).astype(np.int64)
    labels = frame["label"].astype(np.float32).to_numpy()
    return encoded, labels


def _infer_logits(model: Any, encoded: np.ndarray, device: Any, batch_size: int) -> np.ndarray:
    torch, _, DataLoader, TensorDataset = _require_torch()
    loader = DataLoader(TensorDataset(torch.from_numpy(encoded)), batch_size=batch_size, shuffle=False)
    result = []
    model.eval()
    with torch.inference_mode():
        for (values,) in loader:
            result.append(model(values.to(device)).detach().cpu().numpy())
    return np.concatenate(result).astype(float)


def _sigmoid(values: np.ndarray) -> np.ndarray:
    values = np.clip(values, -40.0, 40.0)
    return 1.0 / (1.0 + np.exp(-values))


def _logit(values: np.ndarray) -> np.ndarray:
    clipped = np.clip(values, 1e-6, 1.0 - 1e-6)
    return np.log(clipped / (1.0 - clipped))


def _fit_sigmoid(logits: np.ndarray, labels: np.ndarray) -> Tuple[float, float]:
    calibrator = LogisticRegression(C=10.0, solver="lbfgs", random_state=SEED)
    calibrator.fit(logits.reshape(-1, 1), labels.astype(int))
    return float(calibrator.coef_[0, 0]), float(calibrator.intercept_[0])


def _calibrated_probabilities(logits: np.ndarray, slope: float, intercept: float) -> np.ndarray:
    return _sigmoid(slope * logits + intercept)


def _ensemble_search(
    rf_cal: np.ndarray,
    tcn_cal: np.ndarray,
    y_cal: np.ndarray,
    rf_policy: np.ndarray,
    tcn_policy: np.ndarray,
    y_policy: np.ndarray,
) -> Tuple[Dict[str, float], Dict[str, Dict[str, Any]]]:
    reports: Dict[str, Dict[str, Any]] = {}
    contracts: Dict[str, Dict[str, float]] = {}
    for weight in np.linspace(0.0, 0.4, 9):
        cal_blend = (1.0 - weight) * rf_cal + weight * tcn_cal
        slope, intercept = _fit_sigmoid(_logit(cal_blend), y_cal)
        if slope <= 0:
            continue
        policy_blend = (1.0 - weight) * rf_policy + weight * tcn_policy
        policy_prob = _calibrated_probabilities(_logit(policy_blend), slope, intercept)
        name = f"tcn_weight_{weight:.2f}"
        reports[name] = {
            "policy_at_0_5": metrics(y_policy, policy_prob),
            "policy_zero_observed_fp": zero_observed_fp_metrics(y_policy, policy_prob),
        }
        contracts[name] = {"tcn_weight": float(weight), "slope": slope, "intercept": intercept}
    if not reports:
        raise RuntimeError("No valid RF/TCN ensemble calibration candidate")
    selected = max(
        reports,
        key=lambda name: (
            reports[name]["policy_zero_observed_fp"]["recall"],
            reports[name]["policy_at_0_5"]["pr_auc"],
            reports[name]["policy_at_0_5"]["roc_auc"],
            -reports[name]["policy_at_0_5"]["brier"],
        ),
    )
    reports["selected"] = {"name": selected}  # type: ignore[assignment]
    return contracts[selected], reports


def _eligible_splits(dataset_path: Path) -> Dict[str, pd.DataFrame]:
    frame = pd.read_csv(dataset_path)
    eligible = frame[frame.get("training_eligible", pd.Series([1] * len(frame))).astype(int).eq(1)].copy()
    splits = {
        name: eligible[eligible["split"].eq(name)].reset_index(drop=True)
        for name in ("train", "calibration", "policy", "test")
    }
    for name, split in splits.items():
        if split.empty or split["label"].nunique() != 2:
            raise ValueError(f"TCN split {name!r} must contain both labels")
    return splits


def _rf_probabilities(artifact: DetectorArtifact, splits: Dict[str, pd.DataFrame]) -> Dict[str, np.ndarray]:
    return {
        name: artifact.rf_model.predict_proba(split[FEATURE_COLUMNS].astype(float).to_numpy())[:, 1]
        for name, split in splits.items()
    }


def train_tcn(
    dataset_path: Path,
    rf_artifact_path: Path,
    output_onnx: Path,
    output_artifact: Path,
    *,
    epochs: int = 20,
    patience: int = 4,
    batch_size: int = 128,
    learning_rate: float = 1e-3,
    resume_checkpoint: Path | None = None,
) -> Dict[str, Any]:
    torch, nn, DataLoader, TensorDataset = _require_torch()
    random.seed(SEED)
    np.random.seed(SEED)
    torch.manual_seed(SEED)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(SEED)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    splits = _eligible_splits(dataset_path)
    encoded = {name: _encode_frame(split) for name, split in splits.items()}

    train_x, train_y = encoded["train"]
    train_loader = DataLoader(
        TensorDataset(torch.from_numpy(train_x), torch.from_numpy(train_y)),
        batch_size=batch_size,
        shuffle=True,
        generator=torch.Generator().manual_seed(SEED),
    )
    model = URLTCN().to(device)
    resumed_from = ""
    if resume_checkpoint is not None:
        checkpoint = torch.load(str(resume_checkpoint), map_location=device, weights_only=True)
        model.load_state_dict(checkpoint["state_dict"])
        resumed_from = str(resume_checkpoint)
    positive = float(train_y.sum())
    negative = float(len(train_y) - positive)
    criterion = nn.BCEWithLogitsLoss(pos_weight=torch.tensor(negative / max(positive, 1.0), device=device))
    optimizer = torch.optim.AdamW(model.parameters(), lr=learning_rate, weight_decay=1e-4)
    scheduler = torch.optim.lr_scheduler.ReduceLROnPlateau(optimizer, mode="max", factor=0.5, patience=1)
    amp_enabled = device.type == "cuda"
    scaler = torch.cuda.amp.GradScaler(enabled=amp_enabled)

    cal_x, cal_y = encoded["calibration"]
    baseline_logits = _infer_logits(model, cal_x, device, batch_size * 2)
    best_ap = float(average_precision_score(cal_y, _sigmoid(baseline_logits)))
    best_epoch = 0
    best_state = copy.deepcopy(model.state_dict())
    history = []
    stale = 0
    for epoch in range(1, epochs + 1):
        model.train()
        running_loss = 0.0
        seen = 0
        for values, labels in train_loader:
            values = values.to(device)
            labels = labels.to(device)
            optimizer.zero_grad(set_to_none=True)
            amp_context = torch.cuda.amp.autocast if amp_enabled else nullcontext
            with amp_context():
                logits = model(values)
                loss = criterion(logits, labels)
            scaler.scale(loss).backward()
            scaler.unscale_(optimizer)
            torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            scaler.step(optimizer)
            scaler.update()
            running_loss += float(loss.detach().cpu()) * len(labels)
            seen += len(labels)
        cal_logits = _infer_logits(model, cal_x, device, batch_size * 2)
        cal_ap = float(average_precision_score(cal_y, _sigmoid(cal_logits)))
        scheduler.step(cal_ap)
        history.append({"epoch": epoch, "train_loss": running_loss / max(seen, 1), "calibration_pr_auc": cal_ap})
        print(json.dumps(history[-1]), flush=True)
        if cal_ap > best_ap + 1e-4:
            best_ap = cal_ap
            best_epoch = epoch
            best_state = copy.deepcopy(model.state_dict())
            stale = 0
        else:
            stale += 1
        if epoch >= 5 and stale >= patience:
            break
    model.load_state_dict(best_state)
    model.eval()

    raw_logits = {name: _infer_logits(model, values[0], device, batch_size * 2) for name, values in encoded.items()}
    tcn_slope, tcn_intercept = _fit_sigmoid(raw_logits["calibration"], encoded["calibration"][1])
    tcn_prob = {
        name: _calibrated_probabilities(logits, tcn_slope, tcn_intercept)
        for name, logits in raw_logits.items()
    }

    class CalibratedURLTCN(nn.Module):
        def __init__(self, base: Any, slope: float, intercept: float) -> None:
            super().__init__()
            self.base = base
            self.register_buffer("slope", torch.tensor(slope, dtype=torch.float32))
            self.register_buffer("intercept", torch.tensor(intercept, dtype=torch.float32))

        def forward(self, values: Any) -> Any:
            return self.slope * self.base(values) + self.intercept

    calibrated_model = CalibratedURLTCN(model.cpu(), tcn_slope, tcn_intercept)
    export_onnx(calibrated_model, output_onnx)
    checkpoint_path = output_onnx.with_suffix(".pt")
    torch.save(
        {
            "state_dict": model.state_dict(),
            "tokenizer": {
                "type": "utf8_bytes",
                "input_contract": TCN_INPUT_CONTRACT,
                "max_length": MAX_URL_BYTES,
                "byte_offset": 1,
            },
            "calibration": {"slope": tcn_slope, "intercept": tcn_intercept},
            "best_epoch": best_epoch,
            "seed": SEED,
        },
        checkpoint_path,
    )

    artifact = load_artifact(rf_artifact_path)
    rf_prob = _rf_probabilities(artifact, splits)
    combiner, ensemble_candidates = _ensemble_search(
        rf_prob["calibration"], tcn_prob["calibration"], encoded["calibration"][1].astype(int),
        rf_prob["policy"], tcn_prob["policy"], encoded["policy"][1].astype(int),
    )
    combined_prob = {}
    for name in splits:
        blend = (1.0 - combiner["tcn_weight"]) * rf_prob[name] + combiner["tcn_weight"] * tcn_prob[name]
        combined_prob[name] = _calibrated_probabilities(_logit(blend), combiner["slope"], combiner["intercept"])
    y_policy = encoded["policy"][1].astype(int)
    policy = select_thresholds(y_policy, combined_prob["policy"])
    y_test = encoded["test"][1].astype(int)
    report: Dict[str, Any] = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "device": str(device),
        "seed": SEED,
        "resumed_from": resumed_from,
        "best_epoch": best_epoch,
        "history": history,
        "tokenizer": {
            "type": "utf8_bytes",
            "input_contract": TCN_INPUT_CONTRACT,
            "max_length": MAX_URL_BYTES,
            "vocabulary_size": 257,
        },
        "tcn_calibration": {"slope": tcn_slope, "intercept": tcn_intercept},
        "tcn_test_at_0_5": metrics(y_test, tcn_prob["test"]),
        "ensemble_combiner": combiner,
        "ensemble_candidates": ensemble_candidates,
        "ensemble_policy": policy.to_dict(),
        "ensemble_test_at_0_5": metrics(y_test, combined_prob["test"]),
        "ensemble_test_at_policy_threshold": metrics(y_test, combined_prob["test"], policy.phishing_threshold),
        "ensemble_test_zero_observed_fp": zero_observed_fp_metrics(y_test, combined_prob["test"]),
        "onnx_path": output_onnx.name,
        "checkpoint_path": checkpoint_path.name,
    }
    output_onnx.with_name(output_onnx.stem + "_metrics.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    artifact.tcn_model_path = output_onnx.name
    artifact.score_combiner = combiner
    artifact.policy = policy
    artifact.model_version = "v3-realworld-tcn-" + datetime.now(timezone.utc).strftime("%Y%m%d")
    artifact.metadata = {**artifact.metadata, "tcn_and_ensemble": report}
    artifact.save(output_artifact)

    predictions = splits["test"][["sample_id", "url", "label", "group_id"]].copy()
    predictions["rf_probability"] = rf_prob["test"]
    predictions["tcn_probability"] = tcn_prob["test"]
    predictions["combined_probability"] = combined_prob["test"]
    predictions.to_csv(output_onnx.with_name(output_onnx.stem + "_test_predictions.csv"), index=False)
    return report


def calibrate_existing_tcn(
    dataset_path: Path,
    rf_artifact_path: Path,
    output_onnx: Path,
    output_artifact: Path,
) -> Dict[str, Any]:
    """Build the RF/TCN ensemble from an already exported calibrated ONNX TCN.

    This is intentionally separate from training so an interrupted run after
    ONNX export can be finalized without retraining or changing RF features.
    The predictor calls :func:`encode_url`, so the same hostname-only contract
    is used for calibration and runtime inference.
    """
    if not output_onnx.is_file():
        raise FileNotFoundError(f"TCN ONNX model not found: {output_onnx}")

    splits = _eligible_splits(dataset_path)
    predictor = ONNXTCNPredictor(output_onnx)
    tcn_prob = {
        name: np.asarray([predictor.predict(url) for url in split["url"].astype(str)], dtype=float)
        for name, split in splits.items()
    }
    labels = {name: split["label"].astype(int).to_numpy() for name, split in splits.items()}
    artifact = load_artifact(rf_artifact_path)
    rf_prob = _rf_probabilities(artifact, splits)
    combiner, ensemble_candidates = _ensemble_search(
        rf_prob["calibration"], tcn_prob["calibration"], labels["calibration"],
        rf_prob["policy"], tcn_prob["policy"], labels["policy"],
    )
    combined_prob: Dict[str, np.ndarray] = {}
    for name in splits:
        blend = (1.0 - combiner["tcn_weight"]) * rf_prob[name] + combiner["tcn_weight"] * tcn_prob[name]
        combined_prob[name] = _calibrated_probabilities(_logit(blend), combiner["slope"], combiner["intercept"])
    policy = select_thresholds(labels["policy"], combined_prob["policy"])

    checkpoint_path = output_onnx.with_suffix(".pt")
    checkpoint: Dict[str, Any] = {}
    if checkpoint_path.is_file():
        torch, _, _, _ = _require_torch()
        checkpoint = torch.load(str(checkpoint_path), map_location="cpu", weights_only=True)
    tokenizer = checkpoint.get("tokenizer", {})
    if tokenizer.get("input_contract") != TCN_INPUT_CONTRACT:
        raise RuntimeError(
            "Existing TCN checkpoint does not declare the hostname-only input contract; retrain the TCN first"
        )
    report: Dict[str, Any] = {
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "device": "onnxruntime",
        "seed": checkpoint.get("seed", SEED),
        "resumed_from": "",
        "best_epoch": checkpoint.get("best_epoch"),
        "history": [],
        "finalized_from_existing_onnx": True,
        "tokenizer": {
            "type": "utf8_bytes",
            "input_contract": TCN_INPUT_CONTRACT,
            "max_length": MAX_URL_BYTES,
            "vocabulary_size": 257,
        },
        "tcn_calibration": checkpoint.get("calibration", {}),
        "tcn_test_at_0_5": metrics(labels["test"], tcn_prob["test"]),
        "ensemble_combiner": combiner,
        "ensemble_candidates": ensemble_candidates,
        "ensemble_policy": policy.to_dict(),
        "ensemble_test_at_0_5": metrics(labels["test"], combined_prob["test"]),
        "ensemble_test_at_policy_threshold": metrics(
            labels["test"], combined_prob["test"], policy.phishing_threshold
        ),
        "ensemble_test_zero_observed_fp": zero_observed_fp_metrics(labels["test"], combined_prob["test"]),
        "onnx_path": output_onnx.name,
        "checkpoint_path": checkpoint_path.name,
    }
    output_onnx.with_name(output_onnx.stem + "_metrics.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    artifact.tcn_model_path = output_onnx.name
    artifact.score_combiner = combiner
    artifact.policy = policy
    artifact.model_version = "v3-realworld-tcn-" + datetime.now(timezone.utc).strftime("%Y%m%d")
    artifact.metadata = {**artifact.metadata, "tcn_and_ensemble": report}
    artifact.save(output_artifact)

    predictions = splits["test"][["sample_id", "url", "label", "group_id"]].copy()
    predictions["rf_probability"] = rf_prob["test"]
    predictions["tcn_probability"] = tcn_prob["test"]
    predictions["combined_probability"] = combined_prob["test"]
    predictions.to_csv(output_onnx.with_name(output_onnx.stem + "_test_predictions.csv"), index=False)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Train, calibrate, and export the reproducible URL byte TCN")
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--rf-artifact", required=True)
    parser.add_argument("--output-onnx", default="artifacts/v3/url_tcn.onnx")
    parser.add_argument("--output-artifact", default="artifacts/v3/detector_v3_tcn.joblib")
    parser.add_argument("--epochs", type=int, default=20)
    parser.add_argument("--patience", type=int, default=4)
    parser.add_argument("--batch-size", type=int, default=128)
    parser.add_argument("--resume-checkpoint")
    parser.add_argument(
        "--calibrate-existing-onnx",
        action="store_true",
        help="Finalize the ensemble from an existing hostname-only ONNX TCN without retraining it",
    )
    args = parser.parse_args()
    if args.calibrate_existing_onnx:
        report = calibrate_existing_tcn(
            Path(args.dataset), Path(args.rf_artifact), Path(args.output_onnx), Path(args.output_artifact)
        )
    else:
        report = train_tcn(
            Path(args.dataset), Path(args.rf_artifact), Path(args.output_onnx), Path(args.output_artifact),
            epochs=args.epochs, patience=args.patience, batch_size=args.batch_size,
            resume_checkpoint=Path(args.resume_checkpoint) if args.resume_checkpoint else None,
        )
    print(json.dumps({
        "device": report["device"],
        "best_epoch": report["best_epoch"],
        "tcn_test_at_0_5": report["tcn_test_at_0_5"],
        "ensemble_test_at_policy_threshold": report["ensemble_test_at_policy_threshold"],
    }, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
