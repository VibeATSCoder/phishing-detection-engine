import json
from dataclasses import replace
from pathlib import Path

import httpx
from fastapi.testclient import TestClient

from persianphish_detector import __version__
from persianphish_detector import orchestrator
from persianphish_detector.api import create_app
from persianphish_detector.config import DetectorConfig
from persianphish_detector.types import DomainFacts


def config(tmp_path: Path) -> DetectorConfig:
    return DetectorConfig(
        artifact_path=tmp_path / "missing.joblib",
        intel_db_path=tmp_path / "intel.sqlite3",
        review_db_path=tmp_path / "review.sqlite3",
        result_dir=tmp_path / "results",
        use_browser=False,
    )


def test_health_exposes_service_version(tmp_path: Path):
    with TestClient(create_app(config(tmp_path))) as client:
        response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["service_version"] == __version__


def test_ready_exposes_version_without_claiming_missing_models_are_ready(tmp_path: Path):
    with TestClient(create_app(config(tmp_path))) as client:
        response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["service_version"] == __version__
    assert response.json()["ready"] is False


def test_request_can_run_screener_before_review_without_fast_models(tmp_path: Path, monkeypatch):
    cfg = replace(
        config(tmp_path), fast_models_enabled=False,
        jev_base_url="http://provider.test/custom/v1", jev_model="configured-screen",
        agent_base_url="http://reviewer.test", enamad_verify=False,
    )
    monkeypatch.setattr(orchestrator, "resolve_public_addresses", lambda *_: ["8.8.8.8"])

    async def facts(*_args):
        return DomainFacts()

    monkeypatch.setattr(orchestrator, "collect_domain_facts", facts)
    calls = []

    def screen(request):
        calls.append("screen")
        assert request.url.path == "/custom/v1/chat/completions"
        payload = json.loads(request.content)
        assert payload["model"] == "configured-screen"
        packet = json.loads(payload["messages"][-1]["content"])
        assert packet["host"] == "sample.example"
        assert "private-query" not in str(packet)
        assert "hidden-token" not in str(packet)
        assert "visible sample" in packet["visible_text"]
        # An incomplete provider response cannot count as a low-risk score.
        return httpx.Response(200, json={"choices": [{"message": {"content": "{}"}}]})

    def review(request):
        if request.url.path == "/ready":
            return httpx.Response(200, json={"ready": True})
        if request.method == "POST":
            calls.append("review")
            payload = json.loads(request.content)
            assert payload["upstream"]["rf_score"] is None
            assert payload["upstream"]["combined_score"] is None
            return httpx.Response(202, json={"analysis_id": "analysisid"})
        return httpx.Response(200, json={"status": "completed", "result": {
            "verdict_candidate": "suspicious", "risk_score": 0.5, "confidence": 0.5,
        }})

    with TestClient(create_app(cfg)) as client:
        detector = client.app.state.detector
        detector.agent._client = httpx.AsyncClient(
            base_url=cfg.agent_base_url, transport=httpx.MockTransport(review)
        )
        detector.jev._client = httpx.AsyncClient(
            base_url=cfg.jev_base_url, transport=httpx.MockTransport(screen)
        )
        ready = client.get("/ready")
        assert ready.status_code == 200 and not ready.json()["model_loaded"]

        url = "https://sample.example/?id=private-query"
        html = ("<html><head><title>Sample</title></head><body>"
                "<textarea>hidden-token</textarea><script>hidden-token</script>"
                "<main>" + "<p>visible sample for screening</p>" * 25 + "</main></body></html>")
        request = {"url": url, "use_jev": True, "use_rf": True, "browser_evidence": {
            "final_url": url, "dom_html": html,
        }}
        response = client.post("/v1/detect", json=request)
        assert response.status_code == 200
        result = response.json()
        assert calls == ["screen", "review"]
        assert result["verdict"] == "suspicious"
        assert all(value is None for value in result["model_scores"].values())
        assert result["evidence_summary"]["jev"]["error_code"] == "invalid_response_schema"
        assert result["evidence_summary"]["jev"]["risk"] is None
        assert result["evidence_summary"]["agent_review"]["status"] == "completed"

        calls.clear()
        request["use_jev"] = False
        response = client.post("/v1/detect", json=request)
        assert response.status_code == 200 and calls == ["review"]
        assert "jev" not in response.json()["evidence_summary"]

        calls.clear()
        request["use_jev"] = True
        request["browser_evidence"]["http_status"] = 403
        response = client.post("/v1/detect", json=request)
        assert response.json()["verdict"] == "crawl_failed" and calls == []


def test_explicit_pipeline_capabilities_and_input_validation(tmp_path: Path):
    from dataclasses import replace

    settings = replace(config(tmp_path), api_key="test-key")
    with TestClient(create_app(settings)) as client:
        assert client.get("/v1/pipeline").status_code == 401
        headers = {"X-API-Key": "test-key"}
        stages = client.get("/v1/pipeline", headers=headers)
        assert stages.status_code == 200
        assert stages.json()["stages"] == ["rf", "decision", "rag", "agent"]
        for controls in (
            {"pipeline": []}, {"pipeline": ["rf", "rf"]}, {"pipeline": ["unknown"]},
            {"pipeline": ["agent"], "use_rf": True},
        ):
            response = client.post("/v1/detect", headers=headers, json={"url": "https://example.com/", **controls})
            assert response.status_code == 422
