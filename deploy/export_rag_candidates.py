"""Export validated homepage candidates from an existing RAG index without crawling."""

from __future__ import annotations

import json
import os
from pathlib import Path
from urllib.parse import urlsplit

import pyarrow.parquet as pq


def main() -> None:
    index = Path(os.environ.get("RAG_INDEX_DIR", "/data/index")) / "page_index.parquet"
    columns = ["domain", "base_url_used", "validation_passed"]
    parquet = pq.ParquetFile(index)
    # Older index exports contain homepage rows only.
    if "page_type" in parquet.schema.names:
        columns.append("page_type")
    candidates: set[str] = set()
    for batch in parquet.iter_batches(columns=columns, batch_size=1024):
        for row in batch.to_pylist():
            if row["validation_passed"] is not True or row.get("page_type", "homepage") != "homepage":
                continue
            value = row["base_url_used"]
            domain = row["domain"]
            if not isinstance(value, str) or not isinstance(domain, str):
                continue
            try:
                url = urlsplit(value)
            except ValueError:
                continue
            if url.scheme == "https" and url.hostname == domain.lower():
                candidates.add(value)
    print(json.dumps({"format": "persianphish-rag-candidates-v1", "urls": sorted(candidates)}))


if __name__ == "__main__":
    main()
