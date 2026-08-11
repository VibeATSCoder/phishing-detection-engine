"""Exercise the detector -> agentic reviewer boundary without live crawling."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any


HTML = """<!doctype html>
<html lang="en"><head><title>Example Domain</title></head>
<body><main><h1>Example Domain</h1>
<p>This domain is reserved for documentation examples and integration testing.
It contains ordinary visible text and does not request credentials or payments.</p>
</main></body></html>"""


def request_json(
    method: str,
    url: str,
    *,
    body: dict[str, Any] | None = None,
    api_key: str = "",
    timeout: float = 120.0,
) -> tuple[int, dict[str, Any]]:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"accept": "application/json"}
    if data is not None:
        headers["content-type"] = "application/json"
    if api_key:
        headers["x-api-key"] = api_key
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            payload = json.loads(response.read(1_000_001))
            return response.status, payload
    except urllib.error.HTTPError as exc:
        detail = exc.read(1_000_001).decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} returned HTTP {exc.code}: {detail[:500]}") from exc


def run(base_url: str, api_key: str) -> dict[str, Any]:
    base_url = base_url.rstrip("/")
    status, ready = request_json("GET", f"{base_url}/ready", timeout=10)
    if status != 200 or ready.get("ready") is not True or ready.get("agent_ready") is not True:
        raise RuntimeError(f"integrated service is not ready: {ready}")

    suspect_url = "https://example.com/account/login"
    payload = {
        "url": suspect_url,
        "browser_evidence": {
            "final_url": suspect_url,
            "http_status": 200,
            "content_type": "text/html; charset=utf-8",
            "dom_html": HTML,
            "redirect_chain": [suspect_url],
            "network_hosts": ["example.com"],
        },
        "agent_references": [
            {
                "reference_id": "example-official",
                "official_url": "https://example.com/",
                "html": HTML,
                "retrieval_score": 0.99,
                "brand_name": "Example Domain",
            }
        ],
    }
    status, result = request_json(
        "POST", f"{base_url}/v1/detect", body=payload, api_key=api_key, timeout=120
    )
    if status != 200:
        raise RuntimeError(f"unexpected detect status: {status}")
    if result.get("stage") != "agent":
        raise RuntimeError(f"uncertain case did not cross the agent boundary: {result.get('stage')}")
    review = (result.get("evidence_summary") or {}).get("agent_review") or {}
    if review.get("status") != "completed" or review.get("verdict_candidate") != "suspicious":
        raise RuntimeError(f"agent result was not reconciled: {review}")
    if result.get("verdict") != "suspicious":
        raise RuntimeError(f"mock advisory must fail closed to suspicious: {result.get('verdict')}")
    serialized = json.dumps(result).lower()
    for forbidden in ("<!doctype html", "<html", "suspect_html", "reference_html", "integration-test-key"):
        if forbidden in serialized:
            raise RuntimeError(f"raw or secret material leaked into detector result: {forbidden}")
    if not {"rf", "tcn", "combined", "ood_fraction"}.issubset(result.get("model_scores") or {}):
        raise RuntimeError("deterministic model scores are missing")
    return {
        "status": "ok",
        "request_id": result.get("request_id"),
        "verdict": result.get("verdict"),
        "stage": result.get("stage"),
        "agent_analysis_id": review.get("analysis_id"),
        "model_scores": result.get("model_scores"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8088")
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()
    try:
        print(json.dumps(run(args.base_url, args.api_key), indent=2))
    except Exception as exc:
        print(f"integrated smoke failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
