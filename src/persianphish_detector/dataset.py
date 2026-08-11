from __future__ import annotations

import argparse
import csv
import hashlib
import itertools
import json
import os
import re
from concurrent.futures import FIRST_COMPLETED, ProcessPoolExecutor, wait
from dataclasses import asdict
from pathlib import Path
from typing import Dict, Iterable, Iterator, List, Mapping, Optional, Tuple

import pandas as pd

from .crawl.quality import assess_crawl_quality
from .features import FEATURE_COLUMNS, extract_features
from .types import CrawlEvidence, CrawlStatus, DomainFacts
from .url_utils import normalize_url, registrable_domain


ARCHIVE_NAME_RE = re.compile(r"^(?P<date>\d{8})__(?P<domain>.+)__(?P<hash>[0-9a-fA-F]{12})(?:__T\d{2})?\.html$")


def parse_archive_name(path: Path) -> Tuple[str, str, str]:
    match = ARCHIVE_NAME_RE.match(path.name)
    if not match:
        raise ValueError(f"unrecognized archive filename: {path.name}")
    return match.group("date"), match.group("domain").lower(), match.group("hash").lower()


def stable_split(group_id: str) -> str:
    value = int(hashlib.sha256(("v2-realworld||" + group_id).encode("utf-8")).hexdigest()[:12], 16) / float(16**12)
    if value < 0.65:
        return "train"
    if value < 0.77:
        return "calibration"
    if value < 0.88:
        return "policy"
    return "test"


def archived_evidence(url: str, html_path: Path) -> CrawlEvidence:
    data = html_path.read_bytes()
    html = data.decode("utf-8", errors="replace")
    status, score, reasons = assess_crawl_quality(200, "text/html; charset=utf-8", html)
    return CrawlEvidence(
        target_url=normalize_url(url),
        final_url=normalize_url(url),
        status=status,
        http_status=200,
        content_type="text/html; charset=utf-8",
        html=html,
        redirect_chain=[normalize_url(url)],
        source="archive",
        quality_score=score,
        quality_reasons=reasons,
    )


def feature_row(
    *,
    sample_id: str,
    url: str,
    html_path: Path,
    label: int,
    sample_origin: str,
    source_type: str,
    capture_date: str,
    include_partial: bool,
    label_quality: str = "",
    group_id_override: str = "",
    url_technique_id: str = "",
    html_technique_id: str = "",
) -> Tuple[Optional[Dict[str, object]], Optional[Dict[str, object]]]:
    try:
        evidence = archived_evidence(url, html_path)
        date, domain, hash_short = parse_archive_name(html_path)
        group_id = group_id_override or registrable_domain(url)
        issue = None
        if not evidence.usable:
            issue = {
                "sample_id": sample_id,
                "url": url,
                "html_path": str(html_path),
                "label": label,
                "quality_status": evidence.status.value,
                "quality_score": evidence.quality_score,
                "quality_reasons": "|".join(evidence.quality_reasons),
            }
            if not include_partial:
                return None, issue
        features = extract_features(evidence, DomainFacts(registrable_domain=group_id))
        row: Dict[str, object] = {
            "sample_id": sample_id,
            "url": normalize_url(url),
            "label": label,
            "sample_origin": sample_origin,
            "source_type": source_type,
            "label_quality": label_quality or ("verified_legitimate" if label == 0 else "generated_phishing"),
            "group_id": group_id,
            "capture_date": capture_date or date,
            "html_path": str(html_path),
            "quality_status": evidence.status.value,
            "quality_score": evidence.quality_score,
            "split": "weak_stress" if label_quality == "weak_feed" else stable_split(group_id),
            "training_eligible": int(label_quality != "weak_feed"),
            "url_technique_id": url_technique_id,
            "html_technique_id": html_technique_id,
        }
        row.update(features)
        return row, issue
    except Exception as exc:
        return None, {
            "sample_id": sample_id,
            "url": url,
            "html_path": str(html_path),
            "label": label,
            "quality_status": "extract_error",
            "quality_score": 0.0,
            "quality_reasons": f"{type(exc).__name__}:{exc}",
        }


def legitimate_rows(workspace: Path, include_partial: bool) -> Iterator[Tuple[Optional[Dict[str, object]], Optional[Dict[str, object]]]]:
    base = workspace / "\u0645\u062c\u0645\u0648\u0639\u0647 \u062f\u0627\u062f\u0647 \u0642\u0627\u0646\u0648\u0646\u06cc" / "\u0645\u062c\u0645\u0648\u0639\u0647 \u062f\u0627\u062f\u0647 \u0642\u0627\u0646\u0648\u0646\u06cc"
    csv_path = base / "legitimate_filtered.csv"
    archive = base / "legitimate_html_archive"
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for source in csv.DictReader(handle):
            filename = Path(str(source.get("file") or "")).name
            path = archive / filename
            try:
                date, domain, hash_short = parse_archive_name(path)
            except ValueError:
                yield None, {"sample_id": filename, "quality_status": "bad_filename", "quality_reasons": filename}
                continue
            yield feature_row(
                sample_id=f"{date}__{domain}__{hash_short}__legitimate",
                url=f"https://{domain}",
                html_path=path,
                label=0,
                sample_origin="real",
                source_type="legitimate_archive",
                capture_date=date,
                include_partial=include_partial,
                label_quality="verified_legitimate",
            )


def real_phishing_rows(workspace: Path, include_partial: bool) -> Iterator[Tuple[Optional[Dict[str, object]], Optional[Dict[str, object]]]]:
    base = workspace / "\u0645\u062c\u0645\u0648\u0639\u0647 \u062f\u0627\u062f\u0647 \u0641\u06cc\u0634\u06cc\u0646\u06af \u0648\u0627\u0642\u0639\u06cc" / "\u0645\u062c\u0645\u0648\u0639\u0647 \u062f\u0627\u062f\u0647 \u0641\u06cc\u0634\u06cc\u0646\u06af \u0648\u0627\u0642\u0639\u06cc"
    csv_path = base / "2026-02-25_ir_phishing.csv"
    archive = base / "real_test_phishing_html_archive"
    files: Dict[Tuple[str, str], Path] = {}
    domain_files: Dict[str, List[Path]] = {}
    for path in archive.glob("*.html"):
        try:
            _, domain, hash_short = parse_archive_name(path)
        except ValueError:
            continue
        files[(domain, hash_short)] = path
        domain_files.setdefault(domain, []).append(path)
    with csv_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for source in csv.DictReader(handle):
            domain = str(source.get("domain") or "").lower().strip()
            hash_short = str(source.get("hash_short") or "").lower().strip()
            path = files.get((domain, hash_short))
            if path is None and len(domain_files.get(domain, [])) == 1:
                path = domain_files[domain][0]
            if path is None:
                yield None, {
                    "sample_id": f"{domain}__{hash_short}",
                    "url": str(source.get("final_url") or source.get("original_url") or domain),
                    "label": 1,
                    "quality_status": "missing_html",
                    "quality_reasons": "archive_not_found",
                }
                continue
            date, _, _ = parse_archive_name(path)
            url = str(source.get("final_url") or source.get("original_url") or domain)
            yield feature_row(
                sample_id=f"{date}__{domain}__{hash_short}__real_phishing",
                url=url,
                html_path=path,
                label=1,
                sample_origin="real",
                source_type=str(source.get("source") or "real_phishing_archive"),
                capture_date=date,
                include_partial=include_partial,
                label_quality="weak_feed",
            )


def synthetic_rows(workspace: Path, include_partial: bool, limit: int | None = None) -> Iterator[Tuple[Optional[Dict[str, object]], Optional[Dict[str, object]]]]:
    dataset_root = workspace / "balanced_generated_websites_by_technique_20260709"
    metadata_path = workspace / "TCN" / "dataset" / "combined_url_html_feature_metadata.csv"
    seen = 0
    with metadata_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for source in csv.DictReader(handle):
            if source.get("sample_type") != "phishing":
                continue
            target_url = str(source.get("target_url") or "")
            group_id = registrable_domain(target_url)
            html_path = dataset_root / str(source.get("html_path") or "")
            sample_id = str(source.get("sample_id") or html_path.stem)
            date = sample_id.split("__", 1)[0]
            yield feature_row(
                sample_id=sample_id,
                url=str(source.get("url") or source.get("phishing_url") or target_url),
                html_path=html_path,
                label=1,
                sample_origin="synthetic",
                source_type="persianphish_generated",
                capture_date=date,
                include_partial=include_partial,
                label_quality="generated_phishing",
                group_id_override=group_id,
                url_technique_id=str(source.get("url_technique_id") or ""),
                html_technique_id=str(source.get("html_technique_id") or ""),
            )
            seen += 1
            if limit is not None and seen >= limit:
                return


def _run_spec(spec: Dict[str, object]) -> Tuple[Optional[Dict[str, object]], Optional[Dict[str, object]]]:
    return feature_row(**spec)  # type: ignore[arg-type]


def extraction_specs(workspace: Path, include_partial: bool, synthetic_limit: int | None) -> Iterator[Dict[str, object]]:
    legitimate_base = workspace / "\u0645\u062c\u0645\u0648\u0639\u0647 \u062f\u0627\u062f\u0647 \u0642\u0627\u0646\u0648\u0646\u06cc" / "\u0645\u062c\u0645\u0648\u0639\u0647 \u062f\u0627\u062f\u0647 \u0642\u0627\u0646\u0648\u0646\u06cc"
    with (legitimate_base / "legitimate_filtered.csv").open("r", encoding="utf-8-sig", newline="") as handle:
        for source in csv.DictReader(handle):
            path = legitimate_base / "legitimate_html_archive" / Path(str(source.get("file") or "")).name
            try:
                date, domain, hash_short = parse_archive_name(path)
            except ValueError:
                continue
            yield {
                "sample_id": f"{date}__{domain}__{hash_short}__legitimate",
                "url": f"https://{domain}",
                "html_path": path,
                "label": 0,
                "sample_origin": "real",
                "source_type": "legitimate_archive",
                "capture_date": date,
                "include_partial": include_partial,
                "label_quality": "verified_legitimate",
            }

    phishing_base = workspace / "\u0645\u062c\u0645\u0648\u0639\u0647 \u062f\u0627\u062f\u0647 \u0641\u06cc\u0634\u06cc\u0646\u06af \u0648\u0627\u0642\u0639\u06cc" / "\u0645\u062c\u0645\u0648\u0639\u0647 \u062f\u0627\u062f\u0647 \u0641\u06cc\u0634\u06cc\u0646\u06af \u0648\u0627\u0642\u0639\u06cc"
    archive = phishing_base / "real_test_phishing_html_archive"
    files: Dict[Tuple[str, str], Path] = {}
    domain_files: Dict[str, List[Path]] = {}
    for path in archive.glob("*.html"):
        try:
            _, domain, hash_short = parse_archive_name(path)
        except ValueError:
            continue
        files[(domain, hash_short)] = path
        domain_files.setdefault(domain, []).append(path)
    with (phishing_base / "2026-02-25_ir_phishing.csv").open("r", encoding="utf-8-sig", newline="") as handle:
        for source in csv.DictReader(handle):
            domain = str(source.get("domain") or "").lower().strip()
            hash_short = str(source.get("hash_short") or "").lower().strip()
            path = files.get((domain, hash_short))
            if path is None and len(domain_files.get(domain, [])) == 1:
                path = domain_files[domain][0]
            if path is None:
                continue
            date, _, _ = parse_archive_name(path)
            yield {
                "sample_id": f"{date}__{domain}__{hash_short}__real_phishing",
                "url": str(source.get("final_url") or source.get("original_url") or domain),
                "html_path": path,
                "label": 1,
                "sample_origin": "real",
                "source_type": str(source.get("source") or "real_phishing_archive"),
                "capture_date": date,
                "include_partial": include_partial,
                "label_quality": "weak_feed",
            }

    dataset_root = workspace / "balanced_generated_websites_by_technique_20260709"
    metadata_path = workspace / "TCN" / "dataset" / "combined_url_html_feature_metadata.csv"
    selected = 0
    with metadata_path.open("r", encoding="utf-8-sig", newline="") as handle:
        for source in csv.DictReader(handle):
            if source.get("sample_type") != "phishing":
                continue
            target_url = str(source.get("target_url") or "")
            group_id = registrable_domain(target_url)
            sample_id = str(source.get("sample_id") or "")
            yield {
                "sample_id": sample_id,
                "url": str(source.get("url") or source.get("phishing_url") or target_url),
                "html_path": dataset_root / str(source.get("html_path") or ""),
                "label": 1,
                "sample_origin": "synthetic",
                "source_type": "persianphish_generated",
                "capture_date": sample_id.split("__", 1)[0],
                "include_partial": include_partial,
                "label_quality": "generated_phishing",
                "group_id_override": group_id,
                "url_technique_id": str(source.get("url_technique_id") or ""),
                "html_technique_id": str(source.get("html_technique_id") or ""),
            }
            selected += 1
            if synthetic_limit is not None and selected >= synthetic_limit:
                break


def build_dataset(
    workspace: Path,
    output: Path,
    issues_output: Path,
    *,
    include_partial: bool = False,
    synthetic_limit: int | None = None,
    progress_every: int = 500,
    workers: int | None = None,
    max_total: int | None = None,
) -> Dict[str, object]:
    rows: List[Dict[str, object]] = []
    issues: List[Dict[str, object]] = []
    processed = 0
    worker_count = workers or 1
    all_specs = extraction_specs(workspace, include_partial, synthetic_limit)
    specs = iter(itertools.islice(all_specs, max_total)) if max_total is not None else iter(all_specs)
    if worker_count == 1:
        result_iterator = (_run_spec(spec) for spec in specs)
        for row, issue in result_iterator:
            processed += 1
            if row:
                rows.append(row)
            if issue:
                issues.append(issue)
            if progress_every and processed % progress_every == 0:
                print(f"processed={processed} accepted={len(rows)} issues={len(issues)}", flush=True)
    else:
        with ProcessPoolExecutor(max_workers=worker_count) as executor:
            pending = set()
            exhausted = False
            while pending or not exhausted:
                while not exhausted and len(pending) < worker_count * 4:
                    try:
                        pending.add(executor.submit(_run_spec, next(specs)))
                    except StopIteration:
                        exhausted = True
                if not pending:
                    break
                completed, pending = wait(pending, return_when=FIRST_COMPLETED)
                for future in completed:
                    row, issue = future.result()
                    processed += 1
                    if row:
                        rows.append(row)
                    if issue:
                        issues.append(issue)
                    if progress_every and processed % progress_every == 0:
                        print(f"processed={processed} accepted={len(rows)} issues={len(issues)}", flush=True)
    # Domain-list captures are weak labels. If the same registrable domain is
    # present in the verified legitimate corpus, the rendered page cannot be
    # trusted as a phishing positive and is quarantined instead of teaching a
    # contradictory target to the model.
    legitimate_groups = {
        str(row["group_id"])
        for row in rows
        if row.get("label_quality") == "verified_legitimate"
    }
    curated_rows: List[Dict[str, object]] = []
    weak_seen: set[str] = set()
    trusted_seen: set[str] = set()
    quality_priority = {"verified_legitimate": 0, "generated_phishing": 1, "weak_feed": 2}
    ordered_rows = sorted(
        rows,
        key=lambda item: (
            quality_priority.get(str(item.get("label_quality", "")), 3),
            -float(item.get("quality_score", 0.0)),
            str(item.get("sample_id", "")),
        ),
    )
    for row in ordered_rows:
        canonical = normalize_url(str(row.get("url", ""))).rstrip("/").lower()
        if row.get("label_quality") == "weak_feed":
            if str(row.get("group_id", "")) in legitimate_groups:
                issues.append({
                    "sample_id": row.get("sample_id"),
                    "url": row.get("url"),
                    "html_path": row.get("html_path"),
                    "label": row.get("label"),
                    "quality_status": "label_conflict",
                    "quality_score": row.get("quality_score", 0.0),
                    "quality_reasons": "weak_feed_domain_present_in_verified_legitimate_corpus",
                })
                continue
            if canonical in weak_seen:
                issues.append({
                    "sample_id": row.get("sample_id"),
                    "url": row.get("url"),
                    "html_path": row.get("html_path"),
                    "label": row.get("label"),
                    "quality_status": "duplicate",
                    "quality_score": row.get("quality_score", 0.0),
                    "quality_reasons": "duplicate_weak_feed_url",
                })
                continue
            weak_seen.add(canonical)
        elif canonical in trusted_seen:
            issues.append({
                "sample_id": row.get("sample_id"),
                "url": row.get("url"),
                "html_path": row.get("html_path"),
                "label": row.get("label"),
                "quality_status": "duplicate",
                "quality_score": row.get("quality_score", 0.0),
                "quality_reasons": "duplicate_trusted_canonical_url",
            })
            continue
        else:
            trusted_seen.add(canonical)
        curated_rows.append(row)
    rows = sorted(curated_rows, key=lambda item: str(item.get("sample_id", "")))

    workspace_root = workspace.resolve()
    for collection in (rows, issues):
        for item in collection:
            raw_path = item.get("html_path")
            if not raw_path:
                continue
            try:
                item["html_path"] = Path(str(raw_path)).resolve().relative_to(workspace_root).as_posix()
            except (OSError, ValueError):
                item["html_path"] = Path(str(raw_path)).name

    output.parent.mkdir(parents=True, exist_ok=True)
    pd.DataFrame(rows).to_csv(output, index=False, encoding="utf-8")
    pd.DataFrame(issues).to_csv(issues_output, index=False, encoding="utf-8")
    frame = pd.DataFrame(rows)
    summary: Dict[str, object] = {
        "processed": processed,
        "accepted": len(rows),
        "issues": len(issues),
        "labels": frame["label"].value_counts().to_dict() if not frame.empty else {},
        "origins": frame["sample_origin"].value_counts().to_dict() if not frame.empty else {},
        "label_quality": frame["label_quality"].value_counts().to_dict() if not frame.empty else {},
        "training_eligible": int(frame["training_eligible"].sum()) if not frame.empty else 0,
        "splits": frame.groupby(["split", "label"]).size().unstack(fill_value=0).to_dict(orient="index") if not frame.empty else {},
        "feature_count": len(FEATURE_COLUMNS),
        "workers": worker_count,
    }
    output.with_name(output.stem + "_summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the real-world V3 feature dataset")
    parser.add_argument("--workspace", default="..")
    parser.add_argument("--output", default="data/processed/realworld_v2_features.csv")
    parser.add_argument("--issues-output", default="data/processed/realworld_v2_quality_issues.csv")
    parser.add_argument("--include-partial", action="store_true")
    parser.add_argument("--synthetic-limit", type=int)
    parser.add_argument("--progress-every", type=int, default=500)
    parser.add_argument("--workers", type=int)
    parser.add_argument("--max-total", type=int)
    args = parser.parse_args()
    summary = build_dataset(
        Path(args.workspace).resolve(),
        Path(args.output),
        Path(args.issues_output),
        include_partial=args.include_partial,
        synthetic_limit=args.synthetic_limit,
        progress_every=args.progress_every,
        workers=args.workers,
        max_total=args.max_total,
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
