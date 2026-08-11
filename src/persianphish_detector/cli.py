from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .config import DetectorConfig
from .intel import IntelStore, download_feed
from .models.train_rf import train
from .orchestrator import Detector
from .review import ReviewStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="persianphish-detect", description="PersianPhish real-world detector V3")
    sub = parser.add_subparsers(dest="command", required=True)

    detect = sub.add_parser("detect", help="Detect one URL")
    detect.add_argument("--url", required=True)
    detect.add_argument("--browser-evidence-json")
    detect.add_argument("--no-browser", action="store_true")

    serve = sub.add_parser("serve", help="Run the FastAPI service")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8088)
    serve.add_argument("--workers", type=int, default=1)

    train_cmd = sub.add_parser("train", help="Tune and train the calibrated RF V3 artifact")
    train_cmd.add_argument("--dataset", required=True)
    train_cmd.add_argument("--output", default="artifacts/v3/detector_v3.joblib")
    train_cmd.add_argument("--n-jobs", type=int, default=1)
    train_cmd.add_argument("--search-estimators", type=int, default=700)

    tcn_cmd = sub.add_parser("train-tcn", help="Train URL TCN, export ONNX, and calibrate the RF/TCN ensemble")
    tcn_cmd.add_argument("--dataset", required=True)
    tcn_cmd.add_argument("--rf-artifact", default="artifacts/v3/detector_v3.joblib")
    tcn_cmd.add_argument("--output-onnx", default="artifacts/v3/url_tcn.onnx")
    tcn_cmd.add_argument("--output-artifact", default="artifacts/v3/detector_v3_tcn.joblib")
    tcn_cmd.add_argument("--epochs", type=int, default=20)
    tcn_cmd.add_argument("--patience", type=int, default=4)
    tcn_cmd.add_argument("--batch-size", type=int, default=256)
    tcn_cmd.add_argument("--resume-checkpoint")

    ingest = sub.add_parser("ingest", help="Import a local intelligence feed")
    ingest.add_argument("--format", choices=["openphish", "phishtank", "verified-benign"], required=True)
    ingest.add_argument("--file", required=True)
    ingest.add_argument("--db", default="var/intel.sqlite3")

    download = sub.add_parser("download-feed", help="Download a feed without crawling its URLs")
    download.add_argument("--url", required=True)
    download.add_argument("--output", required=True)

    review = sub.add_parser("review", help="List or resolve review cases")
    review.add_argument("--db", default="var/review.sqlite3")
    review.add_argument("--resolve")
    review.add_argument("--label", choices=["legitimate", "phishing", "crawl_failed", "discard"])
    review.add_argument("--note", default="")
    review.add_argument("--limit", type=int, default=50)
    review.add_argument("--export")
    return parser


async def run_detect(args: argparse.Namespace) -> int:
    config = DetectorConfig.from_env()
    if args.no_browser:
        config = DetectorConfig(**{**config.__dict__, "use_browser": False})
    detector = Detector(config)
    try:
        browser_evidence = None
        if args.browser_evidence_json:
            browser_evidence = json.loads(Path(args.browser_evidence_json).read_text(encoding="utf-8"))
        result = await detector.detect(args.url, browser_evidence)
        print(json.dumps(result.to_dict(), ensure_ascii=False, indent=2))
    finally:
        await detector.close()
    return 0


def main() -> int:
    args = build_parser().parse_args()
    if args.command == "detect":
        return asyncio.run(run_detect(args))
    if args.command == "serve":
        import uvicorn

        uvicorn.run("persianphish_detector.api:app", host=args.host, port=args.port, workers=args.workers)
        return 0
    if args.command == "train":
        report = train(
            Path(args.dataset), Path(args.output), n_jobs=args.n_jobs,
            search_estimators=args.search_estimators,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    if args.command == "train-tcn":
        from .models.train_tcn import train_tcn

        report = train_tcn(
            Path(args.dataset), Path(args.rf_artifact), Path(args.output_onnx), Path(args.output_artifact),
            epochs=args.epochs, patience=args.patience, batch_size=args.batch_size,
            resume_checkpoint=Path(args.resume_checkpoint) if args.resume_checkpoint else None,
        )
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    if args.command == "ingest":
        store = IntelStore(Path(args.db))
        if args.format == "openphish":
            count = store.import_openphish(Path(args.file))
        elif args.format == "phishtank":
            count = store.import_phishtank(Path(args.file))
        else:
            count = store.import_verified_benign(Path(args.file))
        print(f"imported={count}")
        return 0
    if args.command == "download-feed":
        path = download_feed(args.url, Path(args.output))
        print(path)
        return 0
    if args.command == "review":
        store = ReviewStore(Path(args.db))
        if args.export:
            print(json.dumps({"exported": store.export_resolved(Path(args.export)), "path": args.export}))
        elif args.resolve:
            if not args.label:
                raise SystemExit("--label is required with --resolve")
            print(json.dumps({"resolved": store.resolve(args.resolve, args.label, args.note)}))
        else:
            print(json.dumps(store.pending(args.limit), ensure_ascii=False, indent=2))
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
