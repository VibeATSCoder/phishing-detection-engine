from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, Iterator, Mapping, Optional

from .url_utils import canonical_url, hostname, registrable_domain


@dataclass(frozen=True)
class IntelMatch:
    verdict: str
    source: str
    scope: str
    matched_value: str
    last_seen: str
    metadata: Dict[str, object]


SCHEMA = """
CREATE TABLE IF NOT EXISTS indicators (
    canonical_url TEXT NOT NULL,
    host TEXT NOT NULL,
    registrable_domain TEXT NOT NULL,
    verdict TEXT NOT NULL CHECK (verdict IN ('phishing', 'benign')),
    scope TEXT NOT NULL DEFAULT 'url' CHECK (scope IN ('url', 'host', 'domain')),
    source TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    expires_at TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    PRIMARY KEY (canonical_url, verdict, source)
);
CREATE INDEX IF NOT EXISTS idx_indicators_host ON indicators(host, verdict, scope);
CREATE INDEX IF NOT EXISTS idx_indicators_domain ON indicators(registrable_domain, verdict, scope);
CREATE TABLE IF NOT EXISTS feed_runs (
    source TEXT NOT NULL,
    imported_at TEXT NOT NULL,
    row_count INTEGER NOT NULL,
    sha256 TEXT NOT NULL,
    PRIMARY KEY (source, imported_at)
);
"""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class IntelStore:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(SCHEMA)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.path), timeout=30)
        conn.row_factory = sqlite3.Row
        return conn

    def add(
        self,
        url: str,
        *,
        verdict: str,
        source: str,
        scope: str = "url",
        first_seen: str = "",
        last_seen: str = "",
        expires_at: str | None = None,
        metadata: Mapping[str, object] | None = None,
    ) -> None:
        canonical = canonical_url(url)
        now = utc_now()
        with self.connect() as conn:
            conn.execute(
                """
                INSERT INTO indicators (
                    canonical_url, host, registrable_domain, verdict, scope, source,
                    first_seen, last_seen, expires_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(canonical_url, verdict, source) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    expires_at=excluded.expires_at,
                    metadata_json=excluded.metadata_json
                """,
                (
                    canonical,
                    hostname(canonical),
                    registrable_domain(canonical),
                    verdict,
                    scope,
                    source,
                    first_seen or now,
                    last_seen or now,
                    expires_at,
                    json.dumps(dict(metadata or {}), ensure_ascii=False, sort_keys=True),
                ),
            )

    def lookup(self, url: str) -> Optional[IntelMatch]:
        canonical = canonical_url(url)
        host = hostname(canonical)
        domain = registrable_domain(canonical)
        now = utc_now()
        with self.connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM indicators
                WHERE (expires_at IS NULL OR expires_at > ?)
                  AND (
                    (scope='url' AND canonical_url=?) OR
                    (scope='host' AND host=?) OR
                    (scope='domain' AND registrable_domain=?)
                  )
                ORDER BY
                  CASE verdict WHEN 'phishing' THEN 0 ELSE 1 END,
                  CASE scope WHEN 'url' THEN 0 WHEN 'host' THEN 1 ELSE 2 END,
                  last_seen DESC
                LIMIT 1
                """,
                (now, canonical, host, domain),
            ).fetchone()
        if not row:
            return None
        return IntelMatch(
            verdict=row["verdict"],
            source=row["source"],
            scope=row["scope"],
            matched_value=(
                row["canonical_url"] if row["scope"] == "url"
                else row["host"] if row["scope"] == "host"
                else row["registrable_domain"]
            ),
            last_seen=row["last_seen"],
            metadata=json.loads(row["metadata_json"] or "{}"),
        )

    def import_openphish(self, path: Path, source: str = "openphish") -> int:
        data = Path(path).read_bytes()
        count = 0
        for raw_line in data.decode("utf-8", errors="replace").splitlines():
            url = raw_line.strip()
            if not url or url.startswith("#"):
                continue
            try:
                self.add(url, verdict="phishing", source=source, scope="url")
            except ValueError:
                continue
            count += 1
        self._record_run(source, data, count)
        return count

    def import_phishtank(self, path: Path, source: str = "phishtank") -> int:
        data = Path(path).read_bytes()
        text = data.decode("utf-8-sig", errors="replace")
        count = 0
        if Path(path).suffix.lower() == ".json":
            rows = json.loads(text)
        else:
            rows = csv.DictReader(text.splitlines())
        for row in rows:
            url = str(row.get("url") or "").strip()
            verified = str(row.get("verified") or "yes").lower()
            online = str(row.get("online") or "yes").lower()
            if not url or verified not in {"yes", "true", "1"} or online not in {"yes", "true", "1"}:
                continue
            try:
                self.add(
                    url,
                    verdict="phishing",
                    source=source,
                    scope="url",
                    first_seen=str(row.get("submission_time") or ""),
                    last_seen=str(row.get("verification_time") or ""),
                    metadata={"target": row.get("target"), "phish_id": row.get("phish_id")},
                )
            except ValueError:
                continue
            count += 1
        self._record_run(source, data, count)
        return count

    def import_verified_benign(
        self,
        path: Path,
        source: str = "verified_legitimate_archive",
        scope: str = "host",
    ) -> int:
        data = Path(path).read_bytes()
        rows = csv.DictReader(data.decode("utf-8-sig", errors="replace").splitlines())
        values = []
        now = utc_now()
        for row in rows:
            if row.get("label_quality") and row.get("label_quality") != "verified_legitimate":
                continue
            if row.get("label") not in (None, "", "0", 0):
                continue
            url = str(row.get("url") or "").strip()
            if not url:
                continue
            try:
                canonical = canonical_url(url)
            except ValueError:
                continue
            values.append((
                canonical,
                hostname(canonical),
                registrable_domain(canonical),
                "benign",
                scope,
                source,
                now,
                str(row.get("capture_date") or now),
                None,
                json.dumps(
                    {"sample_id": row.get("sample_id"), "quality": row.get("quality_score")},
                    ensure_ascii=False,
                    sort_keys=True,
                ),
            ))
        with self.connect() as conn:
            conn.executemany(
                """
                INSERT INTO indicators (
                    canonical_url, host, registrable_domain, verdict, scope, source,
                    first_seen, last_seen, expires_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(canonical_url, verdict, source) DO UPDATE SET
                    last_seen=excluded.last_seen,
                    expires_at=excluded.expires_at,
                    metadata_json=excluded.metadata_json
                """,
                values,
            )
        count = len(values)
        self._record_run(source, data, count)
        return count

    def _record_run(self, source: str, data: bytes, count: int) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO feed_runs(source, imported_at, row_count, sha256) VALUES (?, ?, ?, ?)",
                (source, utc_now(), count, hashlib.sha256(data).hexdigest()),
            )


def download_feed(url: str, destination: Path, user_agent: str = "PersianPhish-Research-Detector/2.0") -> Path:
    import urllib.request

    request = urllib.request.Request(url, headers={"User-Agent": user_agent})
    with urllib.request.urlopen(request, timeout=60) as response:
        data = response.read(100_000_000)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_bytes(data)
    return destination
