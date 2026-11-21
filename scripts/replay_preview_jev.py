"""Replay static preview captures through the detector API with the local JEV model."""

from __future__ import annotations

import argparse
import csv
import json
from dataclasses import replace
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from fastapi.testclient import TestClient

from persianphish_detector.api import create_app
from persianphish_detector.config import DetectorConfig
from persianphish_detector.types import DomainFacts


ENGINE = Path(__file__).resolve().parents[1]
CONTROL_BRANDS = {"filimo.com", "digikala.com", "digikala.ir", "snapp.ir", "snappfood.ir", "snappshop.ir"}


async def archived_facts(*_args):
    return DomainFacts()


def examples(scenario_dir: Path, capture_dir: Path | None, paper_root: Path | None) -> list[dict]:
    items = json.loads((scenario_dir / "manifest.json").read_text(encoding="utf-8"))["items"]
    cases = []
    for item in items:
        path = capture_dir / f"{item['id']}.html" if capture_dir else scenario_dir / item["page_file"]
        data = path.read_bytes()
        if not capture_dir and not sha256(data).hexdigest().startswith(item["sha256_html"]):
            raise ValueError(f"frozen snapshot changed for {item['id']}")
        cases.append({
            "case": item["id"], "label": "phishing", "url": item["source_url"],
            "html": data[:5_000_000].decode("utf-8", errors="replace"),
        })
    if paper_root:
        controls = {}
        for subset in ("test", "validation", "train"):
            directory = paper_root / subset
            with (directory / "metadata.csv").open(encoding="utf-8", newline="") as source:
                for row in csv.DictReader(source):
                    brand = row["brand_domain"]
                    path = directory / row["html_path"]
                    if row["label"] == "0" and brand in CONTROL_BRANDS and brand not in controls and path.is_file():
                        controls[brand] = {
                            "case": brand, "label": "legitimate", "url": row["target_url"],
                            "html": path.read_bytes()[:5_000_000].decode("utf-8", errors="replace"),
                            "control_split": subset,
                        }
        if controls.keys() != CONTROL_BRANDS:
            raise ValueError(f"missing legitimate controls: {CONTROL_BRANDS - controls.keys()}")
        cases.extend(controls[brand] for brand in sorted(controls))
    return cases


def replay(cases: list[dict], model_path: Path) -> None:
    with TemporaryDirectory() as directory, patch(
        "persianphish_detector.orchestrator.collect_domain_facts", archived_facts,
    ), patch(
        "persianphish_detector.orchestrator.resolve_public_addresses", return_value=["8.8.8.8"],
    ):
        tmp = Path(directory)
        cfg = DetectorConfig(
            artifact_path=ENGINE / "artifacts/v3/detector_v3_tcn.joblib",
            intel_db_path=tmp / "intel.sqlite", review_db_path=tmp / "review.sqlite",
            result_dir=tmp / "results", use_browser=False, enamad_verify=False,
            jev_local_model_path=model_path,
        )
        for mode, use_jev, auto_flag in (
            ("rf_tcn", False, False), ("jev_guard", True, False), ("jev_auto_flag", True, True),
        ):
            with TestClient(create_app(replace(cfg, jev_local_auto_flag=auto_flag))) as client:
                ready = client.get("/ready")
                ready.raise_for_status()
                assert ready.json()["jev_local_configured"]
                for item in cases:
                    res = client.post("/v1/detect", json={
                        "url": item["url"], "use_jev": use_jev,
                        "browser_evidence": {"final_url": item["url"], "dom_html": item["html"]},
                    })
                    res.raise_for_status()
                    result = res.json()
                    audit = result["evidence_summary"].get("jev_local", {})
                    print(json.dumps({
                        "mode": mode, "case": item["case"], "label": item["label"],
                        "control_split": item.get("control_split"),
                        "verdict": result["verdict"], "stage": result["stage"],
                        "crawl_status": result["crawl_status"],
                        "rf_tcn": result["model_scores"].get("combined"), "jev": audit.get("risk"),
                    }), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--local-model", type=Path, default=ENGINE / "artifacts/v3/jev_local_isolated.joblib")
    parser.add_argument("--scenario-dir", type=Path, required=True, help="Local frozen dataset directory")
    parser.add_argument("--capture-dir", type=Path, help="Directory containing saved current preview HTML")
    parser.add_argument("--paper-root", type=Path, help="Optional paper archive root for six legitimate controls")
    args = parser.parse_args()
    replay(examples(args.scenario_dir, args.capture_dir, args.paper_root), args.local_model)


if __name__ == "__main__":
    main()
