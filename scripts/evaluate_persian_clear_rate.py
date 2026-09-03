#!/usr/bin/env python3
"""Measure how often the detector clears a real Persian commercial site.

Why this exists
---------------
The shipped benchmark reports 0.21% false positives, and that number is true but
not transferable: 924 of its 935 legitimate rows are `.ir`, 1,565 of them
academic and 141 government. Iranian commercial sites — the population this
detector actually sees — are 11 rows of it. So the legitimate threshold was
tuned to hit a 0.1% false-positive target against a population that is not the
deployment population, and the benchmark cannot notice when that hurts.

This scores live commercial sites instead and prints the trade-off directly:
what fraction of them clear at a given threshold, against what fraction of the
labelled phishing rows would wrongly clear at the same threshold.

It does not change anything. Where the threshold belongs is a risk decision, and
this exists so that decision can be made against the right population.

Usage
-----
    python scripts/evaluate_persian_clear_rate.py --hosts data/evaluation/persian_commercial_hosts.txt

    --detector   base URL of a running detector (default http://127.0.0.1:8088)
    --workers    concurrent detections (default 5; the crawler is the bottleneck)
    --json       write the per-host results somewhere for later analysis

The host list is legitimate by construction: the entries come from the reference
index's legitimate knowledge base. A site that has since been compromised would
show up as an outlier rather than being silently counted as a false positive, so
inspect anything scoring near the phishing threshold before trusting it.
"""

from __future__ import annotations

import argparse
import concurrent.futures as futures
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PREDICTIONS = ROOT / "artifacts" / "v3" / "detector_v3_test_predictions.csv"
THRESHOLDS = (0.024, 0.03, 0.04, 0.05, 0.08, 0.10, 0.15, 0.25)


def detect(base_url: str, host: str, timeout: float) -> dict[str, object]:
    body = json.dumps({"url": f"https://{host}/"}).encode()
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/v1/detect",
        data=body,
        headers={"Content-Type": "application/json"},
    )
    try:
        payload = json.load(urllib.request.urlopen(request, timeout=timeout))
    except Exception as exc:  # unreachable site, detector error, timeout
        return {"host": host, "verdict": "error", "risk": None, "crawl": type(exc).__name__}
    scores = payload.get("model_scores") or {}
    return {
        "host": host,
        "verdict": payload.get("verdict"),
        "risk": payload.get("risk_score"),
        "crawl": payload.get("crawl_status"),
        "rf": scores.get("rf"),
        "tcn": scores.get("tcn"),
        "ood_fraction": scores.get("ood_fraction"),
    }


def phishing_probabilities() -> list[float]:
    """The labelled phishing side, for the cost half of the trade-off."""
    if not PREDICTIONS.exists():
        return []
    import csv

    with PREDICTIONS.open(encoding="utf-8") as handle:
        return [
            float(row["probability"])
            for row in csv.DictReader(handle)
            if row.get("label") == "1"
        ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--hosts", type=Path,
                        default=ROOT / "data" / "evaluation" / "persian_commercial_hosts.txt")
    parser.add_argument("--detector", default="http://127.0.0.1:8088")
    parser.add_argument("--workers", type=int, default=5)
    parser.add_argument("--timeout", type=float, default=150.0)
    parser.add_argument("--json", type=Path)
    args = parser.parse_args()

    hosts = [
        line.strip()
        for line in args.hosts.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    if not hosts:
        print(f"no hosts in {args.hosts}", file=sys.stderr)
        return 1

    print(f"scoring {len(hosts)} hosts against {args.detector}")
    results: list[dict[str, object]] = []
    with futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        for index, result in enumerate(
            pool.map(lambda h: detect(args.detector, h, args.timeout), hosts), 1
        ):
            results.append(result)
            if index % 25 == 0:
                print(f"  {index}/{len(hosts)}", flush=True)

    if args.json:
        args.json.write_text(
            "\n".join(json.dumps(row) for row in results) + "\n", encoding="utf-8"
        )

    scored = [r for r in results if r["crawl"] == "ok" and r["risk"] is not None]
    print(f"\ncrawled and scored: {len(scored)}/{len(results)}")
    if not scored:
        print("nothing scored; is the detector running?", file=sys.stderr)
        return 1

    risks = sorted(float(r["risk"]) for r in scored)

    def pct(fraction: float) -> float:
        return risks[max(0, int(len(risks) * fraction) - 1)]

    print("\nrisk on legitimate Persian commercial sites")
    for label, fraction in (("median", 0.50), ("p90", 0.90), ("p95", 0.95), ("p99", 0.99)):
        print(f"  {label:>6}  {pct(fraction):.4f}")
    print(f"  {'max':>6}  {risks[-1]:.4f}")

    phishing = phishing_probabilities()
    print("\nthreshold trade-off")
    print(f"  {'threshold':<11} {'these sites cleared':<26} {'phishing wrongly cleared':<26}")
    for threshold in THRESHOLDS:
        cleared = sum(1 for r in risks if r < threshold)
        line = f"  {threshold:<11.4f} {f'{cleared}/{len(risks)} ({cleared / len(risks) * 100:.1f}%)':<26}"
        if phishing:
            wrong = sum(1 for p in phishing if p < threshold)
            line += f" {f'{wrong}/{len(phishing)} ({wrong / len(phishing) * 100:.2f}%)':<26}"
        else:
            line += " (predictions artifact missing)"
        print(line)

    # Anything near the phishing threshold is either a genuinely compromised
    # entry in the host list or a real false positive worth looking at by hand.
    outliers = sorted(scored, key=lambda r: -float(r["risk"]))[:5]
    print("\nhighest-scoring entries, worth inspecting by hand")
    for row in outliers:
        print(f"  {row['host']:<32} {float(row['risk']):.4f}  {row['verdict']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
