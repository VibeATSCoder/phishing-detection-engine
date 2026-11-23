from __future__ import annotations

import argparse
import hashlib
import json
import re
import sqlite3
import sys
import time
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .config import DetectorConfig
from .url_utils import is_ip_literal


MAX_CACHE_ENTRIES = 20_000
MAX_REFERENCES = 100_000
MAX_IMPORT_BYTES = 8_000_000
RAG_FORMAT = "persianphish-rag-candidates-v1"
_HOST = re.compile(r"[a-z0-9-]+(?:\.[a-z0-9-]+)+")
_PATH = re.compile(r"/[a-zA-Z0-9/_~.-]*")


def exact_https_url(value: str) -> str | None:
    """Use only URL spellings that cannot alias a different application route."""
    if not value or not value.isascii() or any(ch in value for ch in "%?#\\"):
        return None
    try:
        parsed = urlsplit(value)
        host = parsed.hostname or ""
    except ValueError:
        return None
    path = parsed.path or "/"
    if (
        parsed.scheme != "https"
        or not _HOST.fullmatch(host)
        or parsed.netloc.lower() not in {host, host + ":443"}
        or is_ip_literal(host)
        or "xn--" in host
        or not _PATH.fullmatch(path)
        or "//" in path
        or any(segment in {".", ".."} for segment in path.split("/"))
        or any(ord(ch) <= 32 or ord(ch) == 127 for ch in value)
    ):
        return None
    return f"https://{host}{path}"


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


@dataclass(frozen=True)
class TrustedResult:
    source: str
    risk: float
    confidence: float
    expires_at: float


class TrustedURLStore:
    """Expiring exact-URL decisions shared by detector workers and restarts."""

    def __init__(self, intel_db_path: Path) -> None:
        self.path = intel_db_path.with_name("trusted-urls.sqlite3")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as conn, conn:
            conn.execute("PRAGMA journal_mode = WAL")
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS reference_candidates (
                    url_hash TEXT PRIMARY KEY
                );
                CREATE TABLE IF NOT EXISTS trusted_urls (
                    url_hash TEXT NOT NULL,
                    policy_hash TEXT NOT NULL,
                    source TEXT NOT NULL,
                    risk REAL NOT NULL,
                    confidence REAL NOT NULL,
                    expires_at REAL NOT NULL,
                    PRIMARY KEY (url_hash, policy_hash)
                );
                CREATE INDEX IF NOT EXISTS trusted_urls_expiry ON trusted_urls(expires_at);
            """)

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.path, timeout=0.25)

    def lookup(self, url: str, policy_hash: str) -> TrustedResult | None:
        with closing(self._connect()) as conn:
            row = conn.execute(
                """
                SELECT source, risk, confidence, expires_at FROM trusted_urls
                WHERE url_hash = ? AND policy_hash = ? AND expires_at > ?
                """,
                (_digest(url), policy_hash, time.time()),
            ).fetchone()
        return TrustedResult(*row) if row else None

    def remember(
        self, url: str, policy_hash: str, risk: float, confidence: float, ttl_s: int, rag_ttl_s: int,
    ) -> TrustedResult:
        now = time.time()
        url_hash = _digest(url)
        with closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM trusted_urls WHERE expires_at <= ?", (now,))
            rag_reference = conn.execute(
                "SELECT 1 FROM reference_candidates WHERE url_hash = ?", (url_hash,),
            ).fetchone()
            source = "rag_reference_verified" if rag_reference else "high_confidence_decision"
            expires = now + (max(ttl_s, rag_ttl_s) if rag_reference else ttl_s)
            conn.execute(
                """
                INSERT INTO trusted_urls VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(url_hash, policy_hash) DO UPDATE SET
                    source = excluded.source, risk = excluded.risk,
                    confidence = excluded.confidence, expires_at = excluded.expires_at
                """,
                (url_hash, policy_hash, source, risk, confidence, expires),
            )
            # Keep the entries with the longest remaining verified lifetime.
            conn.execute(
                """
                DELETE FROM trusted_urls WHERE rowid IN (
                    SELECT rowid FROM trusted_urls ORDER BY expires_at DESC, rowid DESC LIMIT -1 OFFSET ?
                )
                """,
                (MAX_CACHE_ENTRIES,),
            )
        return TrustedResult(source, risk, confidence, expires)

    def forget(self, url: str) -> None:
        with closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM trusted_urls WHERE url_hash = ?", (_digest(url),))

    def replace_references(self, urls: list[str]) -> int:
        normalized = {key for value in urls if (key := exact_https_url(value)) is not None}
        if not normalized or len(urls) > MAX_REFERENCES:
            raise ValueError("invalid_reference_candidate_urls")
        with closing(self._connect()) as conn, conn:
            conn.execute("DELETE FROM reference_candidates")
            conn.executemany(
                "INSERT INTO reference_candidates VALUES (?)", ((_digest(url),) for url in normalized),
            )
            conn.execute("""
                DELETE FROM trusted_urls
                WHERE source = 'rag_reference_verified'
                  AND NOT EXISTS (
                    SELECT 1 FROM reference_candidates WHERE url_hash = trusted_urls.url_hash
                  )
            """)
        return len(normalized)


def main() -> None:
    parser = argparse.ArgumentParser(description="Import exact HTTPS candidates from the RAG page index")
    parser.add_argument("action", choices=["import-reference-candidates"])
    parser.parse_args()
    raw = sys.stdin.buffer.read(MAX_IMPORT_BYTES + 1)
    if len(raw) > MAX_IMPORT_BYTES:
        raise ValueError("reference_candidate_manifest_too_large")
    payload = json.loads(raw)
    urls = payload.get("urls") if isinstance(payload, dict) and payload.get("format") == RAG_FORMAT else None
    if not isinstance(urls, list) or len(urls) > MAX_REFERENCES or not all(isinstance(url, str) for url in urls):
        raise ValueError("invalid_reference_candidate_manifest")
    store = TrustedURLStore(DetectorConfig.from_env().intel_db_path)
    print(f"Imported {store.replace_references(urls)} RAG candidate URLs for verification")


if __name__ == "__main__":
    main()
