from __future__ import annotations

import hashlib
import csv
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional


SCHEMA = """
CREATE TABLE IF NOT EXISTS review_cases (
    request_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    url_hash TEXT NOT NULL,
    canonical_url TEXT NOT NULL,
    proposed_verdict TEXT NOT NULL,
    risk_score REAL NOT NULL,
    reason_codes_json TEXT NOT NULL,
    evidence_json TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'resolved')),
    reviewer_label TEXT,
    reviewer_note TEXT,
    resolved_at TEXT
);
CREATE INDEX IF NOT EXISTS idx_review_status_created ON review_cases(status, created_at);
"""


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


class ReviewStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def enqueue(
        self,
        *,
        request_id: str,
        url: str,
        verdict: str,
        risk_score: float,
        reason_codes: List[str],
        evidence: Mapping[str, Any],
    ) -> None:
        safe_evidence = dict(evidence)
        safe_evidence.pop("html", None)
        safe_evidence.pop("screenshot", None)
        with self.connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO review_cases (
                    request_id, created_at, url_hash, canonical_url, proposed_verdict,
                    risk_score, reason_codes_json, evidence_json, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'pending')
                """,
                (
                    request_id,
                    now_utc(),
                    hashlib.sha256(url.encode("utf-8")).hexdigest(),
                    url,
                    verdict,
                    float(risk_score),
                    json.dumps(reason_codes, ensure_ascii=False),
                    json.dumps(safe_evidence, ensure_ascii=False, sort_keys=True),
                ),
            )

    def pending(self, limit: int = 100) -> List[Dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM review_cases WHERE status='pending' ORDER BY created_at LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        return [dict(row) for row in rows]

    def resolve(self, request_id: str, label: str, note: str = "") -> bool:
        if label not in {"legitimate", "phishing", "crawl_failed", "discard"}:
            raise ValueError("invalid_review_label")
        with self.connect() as conn:
            cursor = conn.execute(
                """
                UPDATE review_cases
                SET status='resolved', reviewer_label=?, reviewer_note=?, resolved_at=?
                WHERE request_id=? AND status='pending'
                """,
                (label, note[:2000], now_utc(), request_id),
            )
        return cursor.rowcount == 1

    def export_resolved(self, destination: Path) -> int:
        with self.connect() as conn:
            rows = conn.execute(
                """
                SELECT request_id, created_at, canonical_url, proposed_verdict, risk_score,
                       reviewer_label, reviewer_note, resolved_at, reason_codes_json, evidence_json
                FROM review_cases WHERE status='resolved' ORDER BY resolved_at
                """
            ).fetchall()
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        columns = [
            "request_id", "created_at", "canonical_url", "proposed_verdict", "risk_score",
            "reviewer_label", "reviewer_note", "resolved_at", "reason_codes_json", "evidence_json",
        ]
        with destination.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns)
            writer.writeheader()
            writer.writerows(dict(row) for row in rows)
        return len(rows)
