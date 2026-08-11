import base64
import hashlib

import pytest
from fastapi.testclient import TestClient
from pathlib import Path

from persianphish_detector.api import MAX_REQUEST_BODY_BYTES, AgentReferenceRequest, DetectRequest, create_app
from persianphish_detector.body_limit import RequestBodyLimitMiddleware
from persianphish_detector.config import DetectorConfig
from persianphish_detector.crawl.evidence import from_browser_payload
from persianphish_detector.types import CrawlStatus


def test_browser_payload_never_accepts_403_as_usable():
    result = from_browser_payload(
        "https://soft98.ir",
        {
            "final_url": "https://soft98.ir/",
            "http_status": 403,
            "content_type": "text/html",
            "dom_html": "<html><head><title>403 Forbidden</title></head><body>Forbidden</body></html>",
            "screenshot_base64": base64.b64encode(b"jpeg").decode(),
        },
    )
    assert result.status == CrawlStatus.BLOCKED
    assert not result.usable


def test_browser_payload_rejects_unknown_fields_by_api_schema():
    from persianphish_detector.api import BrowserEvidenceRequest

    with pytest.raises(Exception):
        BrowserEvidenceRequest(
            final_url="https://example.com",
            dom_html="<html></html>",
            cookies="must not be accepted",
        )


def test_optional_api_key_protects_non_health_endpoints(tmp_path: Path):
    config = DetectorConfig(
        artifact_path=tmp_path / "missing.joblib",
        intel_db_path=tmp_path / "intel.sqlite3",
        review_db_path=tmp_path / "review.sqlite3",
        result_dir=tmp_path / "results",
        use_browser=False,
        api_key="secret",
    )
    with TestClient(create_app(config)) as client:
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 503
        assert client.get("/v1/review").status_code == 401
        assert client.get("/v1/review", headers={"x-api-key": "secret"}).status_code == 200


def test_api_rejects_oversized_declared_body(tmp_path: Path):
    config = DetectorConfig(
        artifact_path=tmp_path / "missing.joblib",
        intel_db_path=tmp_path / "intel.sqlite3",
        review_db_path=tmp_path / "review.sqlite3",
        result_dir=tmp_path / "results",
        use_browser=False,
    )
    with TestClient(create_app(config)) as client:
        response = client.post(
            "/v1/detect",
            content=b"{}",
            headers={"content-length": str(MAX_REQUEST_BODY_BYTES + 1)},
        )
        assert response.status_code == 413


@pytest.mark.asyncio
async def test_api_rejects_oversized_streamed_body_without_content_length():
    messages = [
        {"type": "http.request", "body": b"1234", "more_body": True},
        {"type": "http.request", "body": b"5678", "more_body": False},
    ]
    sent = []

    async def receive():
        return messages.pop(0)

    async def send(message):
        sent.append(message)

    async def consume(_scope, inner_receive, _send):
        while (await inner_receive()).get("more_body"):
            pass

    middleware = RequestBodyLimitMiddleware(consume, max_bytes=6)
    await middleware({"type": "http", "headers": []}, receive, send)
    assert sent[0]["type"] == "http.response.start"
    assert sent[0]["status"] == 413


def test_agent_reference_schema_rejects_unknown_fields_and_hash_mismatch():
    html = "<html><body>official evidence</body></html>"
    with pytest.raises(Exception):
        AgentReferenceRequest(
            reference_id="official",
            official_url="https://official.example/",
            html=html,
            retrieval_score=1,
            cookies="not-allowed",
        )
    with pytest.raises(Exception):
        AgentReferenceRequest(
            reference_id="official",
            official_url="https://official.example/",
            html=html,
            retrieval_score=1,
            content_sha256="0" * 64,
        )
    reference = AgentReferenceRequest(
        reference_id="official",
        official_url="https://official.example/",
        html=html,
        retrieval_score=1,
        content_sha256=hashlib.sha256(html.encode()).hexdigest(),
    )
    assert reference.official_url == "https://official.example/"


def test_detect_request_rejects_duplicate_reference_ids():
    reference = {
        "reference_id": "same",
        "official_url": "https://official.example/",
        "html": "<html><body>official evidence</body></html>",
        "retrieval_score": 1,
    }
    with pytest.raises(Exception):
        DetectRequest(url="https://suspect.example/", agent_references=[reference, reference])
