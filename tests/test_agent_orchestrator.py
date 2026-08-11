from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from persianphish_detector.agent import AgentClient, AgentReview, AgentServiceError
from persianphish_detector.config import DetectorConfig
from persianphish_detector import orchestrator as orchestrator_module
from persianphish_detector.orchestrator import Detector
from persianphish_detector.models.policy import DecisionPolicy
from persianphish_detector.types import CrawlEvidence, CrawlStatus, DomainFacts, Verdict


def completed_result(**overrides):
    result = {
        "verdict_candidate": "suspicious",
        "risk_score": 0.5,
        "confidence": 0.49,
        "evidence_codes": [],
        "intent_codes": [],
        "technique_group_codes": [],
        "reasons": ["missing_or_low_quality_reference"],
        "limitations": ["advisory_only"],
        "model": "mock/model",
    }
    result.update(overrides)
    return result


@pytest.mark.asyncio
async def test_agent_client_submits_provided_html_and_polls_only_configured_origin():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "POST":
            payload = json.loads(request.content)
            assert request.url.path == "/api/v1/analyses"
            assert request.headers["x-api-key"] == "internal-secret"
            assert payload["input_mode"] == "provided_html"
            assert payload["suspect_html"] == "<html><body>safe static evidence</body></html>"
            assert payload["upstream"]["combined_score"] == 0.51
            assert "screenshot" not in str(payload).lower()
            return httpx.Response(
                202,
                json={
                    "analysis_id": "abc123",
                    "status": "queued",
                    "status_url": "http://attacker.invalid/steal",
                },
            )
        assert request.url.path == "/api/v1/analyses/abc123"
        return httpx.Response(
            200,
            json={"analysis_id": "abc123", "status": "completed", "result": completed_result()},
        )

    client = AgentClient("http://review:8090", api_key="internal-secret")
    client._client = httpx.AsyncClient(
        base_url="http://review:8090",
        transport=httpx.MockTransport(handler),
        headers=client._headers(),
        follow_redirects=False,
    )
    try:
        result = await client.review(
            suspect_url="https://suspect.example/login",
            suspect_html="<html><body>safe static evidence</body></html>",
            upstream={"request_id": "upstream", "combined_score": 0.51, "reason_codes": ["policy"]},
        )
    finally:
        await client.close()
    assert result.analysis_id == "abc123"
    assert result.verdict_candidate == "suspicious"
    assert [request.url.host for request in requests] == ["review", "review"]


@pytest.mark.asyncio
async def test_agent_client_rejects_sensitive_or_unsupported_result_payloads():
    results = [
        completed_result(html="must-not-cross-boundary"),
        completed_result(evidence_codes=["invented_code"]),
    ]
    for index, result in enumerate(results):
        def handler(request: httpx.Request, selected=result) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(202, json={"analysis_id": f"job{index}", "status": "queued"})
            return httpx.Response(
                200,
                json={"analysis_id": f"job{index}", "status": "completed", "result": selected},
            )

        client = AgentClient("http://review:8090")
        client._client = httpx.AsyncClient(
            base_url="http://review:8090",
            transport=httpx.MockTransport(handler),
        )
        try:
            with pytest.raises(AgentServiceError):
                await client.review(
                    suspect_url="https://suspect.example/",
                    suspect_html="<html><body>usable evidence</body></html>",
                    upstream={},
                )
        finally:
            await client.close()


@pytest.mark.asyncio
async def test_agent_client_timeout_and_failed_job_fail_closed():
    async def run(status_payload: dict, *, timeout_s: float = 0.1) -> str:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.method == "POST":
                return httpx.Response(202, json={"analysis_id": "job123", "status": "queued"})
            return httpx.Response(200, json={"analysis_id": "job123", **status_payload})

        client = AgentClient(
            "http://review:8090",
            timeout_s=timeout_s,
            poll_interval_s=0.01,
        )
        client._client = httpx.AsyncClient(
            base_url="http://review:8090",
            transport=httpx.MockTransport(handler),
        )
        try:
            with pytest.raises(AgentServiceError) as captured:
                await client.review(
                    suspect_url="https://suspect.example/",
                    suspect_html="<html><body>usable evidence</body></html>",
                    upstream={},
                )
            return captured.value.code
        finally:
            await client.close()

    assert await run({"status": "queued"}, timeout_s=0.05) == "agent_poll_timeout"
    assert await run({"status": "failed", "error_code": "workflow_timeouterror"}) == "workflow_timeouterror"


def review(verdict: str, risk: float | None, confidence: float) -> AgentReview:
    return AgentReview(
        analysis_id="review1",
        verdict_candidate=verdict,
        risk_score=risk,
        confidence=confidence,
    )


def usable_evidence() -> CrawlEvidence:
    return CrawlEvidence(
        target_url="https://suspect.example/",
        final_url="https://suspect.example/",
        status=CrawlStatus.OK,
        html="<html><body>usable</body></html>",
        quality_score=1.0,
    )


def base_features() -> dict[str, float]:
    return {
        "external_form_action_count": 0,
        "suspicious_token_count": 0,
        "password_input_count": 0,
        "title_domain_token_overlap": 1,
    }


def test_agent_reconciliation_requires_confidence_and_deterministic_corroboration():
    evidence = usable_evidence()
    risky = {**base_features(), "external_form_action_count": 1}
    verdict, reasons = Detector._reconcile_agent(review("phishing", 0.92, 0.9), risky, 0.7, evidence)
    assert verdict == Verdict.PHISHING
    assert "agent_advisory_phishing_corroborated" in reasons

    verdict, reasons = Detector._reconcile_agent(review("phishing", 0.92, 0.6), risky, 0.7, evidence)
    assert verdict == Verdict.SUSPICIOUS
    assert "agent_advisory_abstained" in reasons

    verdict, reasons = Detector._reconcile_agent(review("phishing", 0.92, 0.9), base_features(), 0.2, evidence)
    assert verdict == Verdict.SUSPICIOUS
    assert "agent_advisory_abstained" in reasons


def test_agent_legitimate_and_crawl_failed_candidates_remain_bounded():
    evidence = usable_evidence()
    verdict, _ = Detector._reconcile_agent(review("legitimate", 0.08, 0.9), base_features(), 0.1, evidence)
    assert verdict == Verdict.LEGITIMATE

    verdict, reasons = Detector._reconcile_agent(review("crawl_failed", None, 0.0), base_features(), 0.1, evidence)
    assert verdict == Verdict.SUSPICIOUS
    assert "agent_input_quality_disagreement" in reasons


def test_detector_tcn_prediction_calls_loaded_onnx_predictor():
    class Predictor:
        def predict(self, url):
            assert url == "https://soft98.ir/"
            return 0.125

    detector = object.__new__(Detector)
    detector.tcn = Predictor()
    assert detector._predict_tcn("https://soft98.ir/") == 0.125


def test_bootstrap_phishing_requires_cross_model_or_concrete_mismatch():
    detector = object.__new__(Detector)
    detector.artifact = SimpleNamespace(policy=DecisionPolicy(0.05, 0.9))
    clean = {
        "external_form_action_count": 0,
        "cross_domain_redirect_count": 0,
        "unicode_confusable_count": 0,
        "password_input_count": 0,
        "title_domain_token_overlap": 0,
    }
    assert not detector._bootstrap_phishing_supported(clean, 0.99, 0.4)
    assert detector._bootstrap_phishing_supported(clean, 0.99, 0.95)
    mismatch = {**clean, "external_form_action_count": 1}
    assert detector._bootstrap_phishing_supported(mismatch, 0.99, None)


class FakeHttp:
    def __init__(self, evidence: CrawlEvidence) -> None:
        self.evidence = evidence
        self.calls = 0

    async def fetch(self, _url: str) -> CrawlEvidence:
        self.calls += 1
        return self.evidence


class FakeIntel:
    def lookup(self, _url: str):
        return None


class FakeReviewStore:
    def __init__(self) -> None:
        self.items = []

    def enqueue(self, **kwargs) -> None:
        self.items.append(kwargs)


class FakePolicy:
    production_ready = True
    max_ood_fraction = 0.5
    phishing_threshold = 0.9

    def __init__(self, verdict: Verdict) -> None:
        self.verdict = verdict

    def decide(self, _score: float, _ood: float) -> Verdict:
        return self.verdict


class FakeArtifact:
    metadata = {}
    tcn_model_path = None
    model_version = "fake-integrated-model"

    def __init__(self, verdict: Verdict) -> None:
        self.policy = FakePolicy(verdict)

    def predict_rf(self, _features):
        return 0.4, 0.0

    def combine_scores(self, _rf, _tcn):
        return 0.4


class FakeTCN:
    def predict(self, _url: str) -> float:
        return 0.4


class FakeAgent:
    def __init__(self, result: AgentReview) -> None:
        self.result = result
        self.calls = []

    async def review(self, **kwargs) -> AgentReview:
        self.calls.append(kwargs)
        return self.result


def make_detector(tmp_path: Path, evidence: CrawlEvidence, verdict: Verdict, agent: FakeAgent) -> Detector:
    detector = object.__new__(Detector)
    detector.config = DetectorConfig(
        artifact_path=tmp_path / "unused.joblib",
        intel_db_path=tmp_path / "intel.sqlite3",
        review_db_path=tmp_path / "review.sqlite3",
        result_dir=tmp_path / "results",
        use_browser=False,
    )
    detector.http = FakeHttp(evidence)
    detector.browser = None
    detector.intel = FakeIntel()
    detector.review = FakeReviewStore()
    detector.artifact = FakeArtifact(verdict)
    detector.tcn = FakeTCN()
    detector.agent = agent
    return detector


@pytest.mark.asyncio
async def test_detector_routes_only_usable_suspicious_case_to_agent(monkeypatch, tmp_path: Path):
    evidence = usable_evidence()
    agent = FakeAgent(review("suspicious", 0.5, 0.49))
    detector = make_detector(tmp_path, evidence, Verdict.SUSPICIOUS, agent)

    async def fake_facts(_url, _allow_private):
        return DomainFacts(registrable_domain="suspect.example", missing=False)

    monkeypatch.setattr(orchestrator_module, "collect_domain_facts", fake_facts)
    monkeypatch.setattr(orchestrator_module, "extract_features", lambda _evidence, _facts: base_features())
    references = [{
        "reference_id": "official",
        "official_url": "https://official.example/",
        "html": "<html><body>official reference</body></html>",
        "retrieval_score": 1.0,
    }]
    result = await detector.detect("https://suspect.example/", agent_references=references)

    assert result.verdict == Verdict.SUSPICIOUS
    assert result.stage == "agent"
    assert len(agent.calls) == 1
    assert agent.calls[0]["suspect_html"] == evidence.html
    assert agent.calls[0]["references"] == references
    assert agent.calls[0]["upstream"]["rf_score"] == 0.4
    assert result.evidence_summary["agent_review"]["status"] == "completed"
    assert "<html" not in json.dumps(result.to_dict()).lower()
    assert len(detector.review.items) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("fast_verdict", [Verdict.LEGITIMATE, Verdict.PHISHING])
async def test_detector_does_not_call_agent_for_confident_fast_paths(
    monkeypatch, tmp_path: Path, fast_verdict: Verdict
):
    agent = FakeAgent(review("phishing", 0.99, 0.99))
    detector = make_detector(tmp_path, usable_evidence(), fast_verdict, agent)

    async def fake_facts(_url, _allow_private):
        return DomainFacts(registrable_domain="suspect.example", missing=False)

    monkeypatch.setattr(orchestrator_module, "collect_domain_facts", fake_facts)
    monkeypatch.setattr(orchestrator_module, "extract_features", lambda _evidence, _facts: base_features())
    result = await detector.detect("https://suspect.example/")
    assert result.verdict == fast_verdict
    assert result.stage == "fast"
    assert agent.calls == []


@pytest.mark.asyncio
async def test_detector_does_not_call_agent_when_crawl_failed(tmp_path: Path):
    failed = CrawlEvidence(
        target_url="https://blocked.example/",
        status=CrawlStatus.BLOCKED,
        quality_reasons=["challenge_page"],
    )
    agent = FakeAgent(review("phishing", 0.99, 0.99))
    detector = make_detector(tmp_path, failed, Verdict.SUSPICIOUS, agent)
    result = await detector.detect("https://blocked.example/")
    assert result.verdict == Verdict.CRAWL_FAILED
    assert agent.calls == []
