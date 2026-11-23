from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from persianphish_detector.agent import AgentClient, AgentReview, AgentServiceError
from persianphish_detector.config import DetectorConfig
from persianphish_detector import orchestrator as orchestrator_module
from persianphish_detector.features import FEATURE_COLUMNS
from persianphish_detector.jev import JevFinding
from persianphish_detector.jev_local import LocalJev
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
            json={"analysis_id": "abc123", "status": "completed", "result": completed_result(
                timings_ms={"rag": 12.5, "analyst": 37, "verifier": True, "unknown": 40},
                review_passes={"analyst": {"verdict_candidate": "legitimate", "risk_score": 0.1}},
            )},
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
    assert result.timings_ms == {"rag": 12.5, "analyst": 37}
    assert result.audit_summary()["review_passes"] == {
        "analyst": {"verdict_candidate": "legitimate", "risk_score": 0.1},
    }
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
        "unicode_confusable_count": 0,
        "cross_domain_redirect_count": 0,
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
    detector.trust = None
    detector.review = FakeReviewStore()
    detector.artifact = FakeArtifact(verdict)
    detector.tcn = FakeTCN()
    detector.agent = agent
    detector.jev = None
    detector.jev_local = None
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
    assert result.latency_ms["fast_models"] >= 0
    assert result.evidence_summary["fast_verdict"] == "suspicious"
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


@pytest.mark.asyncio
@pytest.mark.parametrize("http_status,reason", [(403, "http_403"), (200, "vpn_access_restricted")])
@pytest.mark.parametrize("pipeline", [None, ("rf", "decision", "rag", "agent")])
async def test_detector_stops_on_access_block_before_browser_or_scores(tmp_path: Path, http_status, reason, pipeline):
    from unittest.mock import AsyncMock, Mock

    evidence = CrawlEvidence(
        target_url="https://blocked.example/", source="http", http_status=http_status,
        status=CrawlStatus.BLOCKED, quality_reasons=[reason],
    )
    agent = FakeAgent(review("phishing", 0.99, 0.99))
    detector = make_detector(tmp_path, evidence, Verdict.SUSPICIOUS, agent)
    detector.browser = AsyncMock()
    detector.jev = AsyncMock()
    detector.tcn = Mock()
    agent.retrieve_references = AsyncMock()
    result = await detector.detect(evidence.target_url, use_jev=True, pipeline=pipeline)
    assert result.verdict == Verdict.CRAWL_FAILED
    assert result.reason_codes == ["crawl_not_usable", reason]
    assert result.model_scores == {"rf": None, "tcn": None}
    assert "browser" not in result.latency_ms
    if pipeline:
        assert result.evidence_summary["pipeline"] == [{"stage": stage, "status": "skipped"} for stage in pipeline]
    detector.browser.fetch.assert_not_awaited()
    detector.jev.score.assert_not_awaited()
    detector.tcn.predict.assert_not_called()
    agent.retrieve_references.assert_not_awaited()
    assert agent.calls == []


@pytest.mark.asyncio
async def test_browser_vpn_notice_takes_precedence_over_partial_http(tmp_path: Path):
    from unittest.mock import AsyncMock

    partial = replace(usable_evidence(), status=CrawlStatus.PARTIAL, quality_score=0.4)
    blocked = replace(partial, source="browser", status=CrawlStatus.BLOCKED, quality_score=0.0,
                      quality_reasons=["vpn_access_restricted"])
    agent = FakeAgent(review("phishing", 0.99, 0.99))
    detector = make_detector(tmp_path, partial, Verdict.SUSPICIOUS, agent)
    detector.browser = SimpleNamespace(fetch=AsyncMock(return_value=blocked))
    result = await detector.detect(partial.target_url, pipeline=("decision", "rag", "agent"))
    assert result.verdict == Verdict.CRAWL_FAILED
    assert result.stage == "browser"
    assert result.reason_codes == ["crawl_not_usable", "vpn_access_restricted"]
    assert [step["status"] for step in result.evidence_summary["pipeline"]] == ["skipped"] * 3
    assert not agent.calls


@pytest.fixture
def cascade_inputs(monkeypatch):
    async def facts(_url, _allow_private):
        return DomainFacts()

    features = base_features()
    monkeypatch.setattr(orchestrator_module, "collect_domain_facts", facts)
    monkeypatch.setattr(orchestrator_module, "extract_features", lambda *_: features)
    return features


@pytest.mark.asyncio
async def test_prefetch_overlaps_jev_and_preserves_review_input(tmp_path, cascade_inputs):
    agent = FakeAgent(review("suspicious", 0.5, 0.49))
    evidence = usable_evidence()
    detector = make_detector(tmp_path, evidence, Verdict.SUSPICIOUS, agent)
    detector.config = replace(detector.config, agent_prefetch_references=True)
    jev_started = asyncio.Event()
    prefetch_started = asyncio.Event()

    async def screen(**_kwargs):
        jev_started.set()
        await asyncio.wait_for(prefetch_started.wait(), 1)
        return JevFinding(ok=True, label="phishing", phishing_score=0.8, confidence=0.9)

    async def prefetch(**kwargs):
        await asyncio.wait_for(jev_started.wait(), 1)
        assert kwargs == {"suspect_url": evidence.final_url, "suspect_html": evidence.html}
        prefetch_started.set()

    detector.jev = SimpleNamespace(score=screen)
    agent.prefetch_references = prefetch
    result = await detector.detect(evidence.target_url, use_jev=True)
    assert result.stage == "agent"
    assert "jev_label:phishing" in agent.calls[0]["upstream"]["reason_codes"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "scores, expected",
    [
        ({"phishing_score": 0.1999, "confidence": 0.80}, Verdict.LEGITIMATE),
        ({"phishing_score": 0.20, "confidence": 0.80}, Verdict.SUSPICIOUS),
        ({"phishing_score": 0.01, "confidence": 0.7999}, Verdict.SUSPICIOUS),
        ({"scam_score": 0.60, "confidence": 0.90}, Verdict.SUSPICIOUS),
        ({"label": "suspicious", "confidence": 0.90}, Verdict.SUSPICIOUS),
        (None, Verdict.SUSPICIOUS),
    ],
    ids=["agreement", "risk-boundary", "confidence-boundary", "scam", "abstention", "unconfigured"],
)
async def test_screener_gate_controls_a_fast_clear(tmp_path, cascade_inputs, scores, expected):
    agent = FakeAgent(review("suspicious", 0.5, 0.49))
    detector = make_detector(tmp_path, usable_evidence(), Verdict.LEGITIMATE, agent)
    if scores is not None:
        fields = {"ok": True, "label": "legitimate", **scores}

        async def screen(**kwargs):
            assert kwargs["visible_text"] == "usable"
            return JevFinding(**fields)

        detector.jev = SimpleNamespace(score=screen)

    result = await detector.detect("https://suspect.example/", use_jev=True)

    assert result.verdict == expected
    assert result.model_scores["combined"] == result.risk_score == 0.4
    assert bool(agent.calls) == (expected == Verdict.SUSPICIOUS)
    if agent.calls:
        assert agent.calls[0]["upstream"]["combined_score"] == 0.4
    if scores is None:
        assert "jev_unavailable:jev_not_configured" in result.reason_codes
        assert result.evidence_summary["jev"]["risk"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "risk_feature, expected",
    [
        (None, Verdict.LEGITIMATE),
        ("external_form_action_count", Verdict.SUSPICIOUS),
        ("unicode_confusable_count", Verdict.SUSPICIOUS),
        ("cross_domain_redirect_count", Verdict.SUSPICIOUS),
    ],
)
async def test_standalone_clear_checks_structural_risk(tmp_path, cascade_inputs, risk_feature, expected):
    agent = FakeAgent(review("suspicious", 0.5, 0.49))
    detector = make_detector(tmp_path, usable_evidence(), Verdict.PHISHING, agent)
    detector.config = replace(
        detector.config, jev_base_url="http://screen.example/v1", jev_model="fixture",
        jev_short_circuit_legit=True,
    )

    async def screen(**kwargs):
        return JevFinding(ok=True, phishing_score=0.01, confidence=0.90, label="legitimate")

    detector.jev = SimpleNamespace(score=screen)
    if risk_feature:
        cascade_inputs[risk_feature] = 1

    result = await detector.detect("https://suspect.example/", use_rf=False, use_jev=True)

    assert result.verdict == expected
    assert all(score is None for score in result.model_scores.values())
    assert bool(agent.calls) == (expected == Verdict.SUSPICIOUS)


@pytest.mark.asyncio
async def test_combined_provider_outage_stays_suspicious(tmp_path, cascade_inputs):
    class UnavailableReviewer:
        async def review(self, **kwargs):
            raise AgentServiceError("agent_poll_timeout")

    detector = make_detector(tmp_path, usable_evidence(), Verdict.LEGITIMATE, UnavailableReviewer())

    async def screen(**kwargs):
        return JevFinding(error="http_503")

    detector.jev = SimpleNamespace(score=screen)
    result = await detector.detect("https://suspect.example/", use_jev=True)

    assert result.verdict == Verdict.SUSPICIOUS
    assert result.evidence_summary["jev"]["error_code"] == "http_503"
    assert result.evidence_summary["agent_review"]["error_code"] == "agent_poll_timeout"
    assert detector.review.items[0]["request_id"] == result.request_id


def test_without_fast_score_review_needs_its_own_concrete_support():
    assessment = review("phishing", 0.92, 0.90)
    verdict, _ = Detector._reconcile_agent(assessment, base_features(), None, usable_evidence())
    assert verdict == Verdict.SUSPICIOUS

    grounded = replace(assessment, reasons=["two_pass_phishing_with_concrete_support"])
    verdict, _ = Detector._reconcile_agent(grounded, base_features(), None, usable_evidence())
    assert verdict == Verdict.PHISHING


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "risk, auto_flag, use_jev, expected",
    [
        (0.001, False, True, Verdict.LEGITIMATE),
        (0.01, False, True, Verdict.SUSPICIOUS),
        (0.9, False, True, Verdict.SUSPICIOUS),
        (0.9, True, True, Verdict.PHISHING),
        (float("nan"), False, True, Verdict.SUSPICIOUS),
        (0.9, True, False, Verdict.LEGITIMATE),
    ],
    ids=["below-review", "review-boundary", "flag-disabled", "flag-enabled", "scorer-failure", "jev-skipped"],
)
async def test_local_jev_routes_independently_of_rf(
    tmp_path, cascade_inputs, risk, auto_flag, use_jev, expected,
):
    import numpy as np

    for key in FEATURE_COLUMNS:
        cascade_inputs.setdefault(key, 0.0)
    classifier = SimpleNamespace(predict_proba=lambda _rows: np.asarray([[1 - risk, risk]]))
    agent = FakeAgent(review("suspicious", 0.50, 0.49))
    detector = make_detector(tmp_path, usable_evidence(), Verdict.LEGITIMATE, agent)
    detector.jev_local = LocalJev(classifier, review_threshold=0.01, phishing_threshold=0.80)
    detector.config = replace(
        detector.config, jev_local_model_path=tmp_path / "fixture.joblib", jev_local_auto_flag=auto_flag,
    )

    result = await detector.detect("https://suspect.example/", use_jev=use_jev)

    assert result.verdict == expected
    assert result.model_scores["combined"] == 0.4
    assert bool(agent.calls) == (expected == Verdict.SUSPICIOUS)
    assert "jev" not in result.evidence_summary
    assert ("jev_local" in result.evidence_summary) == use_jev
    if expected == Verdict.PHISHING:
        assert result.stage == "jev_local" and result.risk_score == 0.9
    elif risk != risk:
        assert result.evidence_summary["jev_local"]["risk"] is None


@pytest.mark.asyncio
async def test_remote_screener_cannot_clear_over_local_jev_risk(tmp_path, cascade_inputs):
    import numpy as np

    for key in FEATURE_COLUMNS:
        cascade_inputs.setdefault(key, 0.0)
    classifier = SimpleNamespace(predict_proba=lambda _rows: np.asarray([[0.3, 0.7]]))
    agent = FakeAgent(review("suspicious", 0.50, 0.49))
    detector = make_detector(tmp_path, usable_evidence(), Verdict.LEGITIMATE, agent)
    detector.jev_local = LocalJev(classifier, review_threshold=0.01, phishing_threshold=0.80)
    detector.config = replace(
        detector.config, jev_base_url="http://screen.example/v1", jev_model="fixture",
        jev_short_circuit_legit=True, jev_local_model_path=tmp_path / "fixture.joblib",
    )

    async def screen(**_kwargs):
        return JevFinding(ok=True, phishing_score=0.01, confidence=0.95, label="legitimate")

    detector.jev = SimpleNamespace(score=screen)
    result = await detector.detect("https://suspect.example/", use_rf=False, use_jev=True)

    assert result.verdict == Verdict.SUSPICIOUS
    assert "jev_local_review_threshold" in result.reason_codes
    assert "jev_short_circuit_legit" not in result.reason_codes
    assert len(agent.calls) == 1


def test_reference_matches_are_surfaced_in_the_agent_review():
    """The RAG reference comparison the reviewer computes must reach the
    detector's response, so an operator can see what the index matched."""
    result = completed_result(
        verdict_candidate="phishing",
        risk_score=0.9,
        confidence=0.9,
        reference_matches=[
            {
                "reference_id": "rag_0_x",
                "official_url": "https://digikala.com/",
                "retrieval_score": 0.7461,
                "reference_quality": 0.52,
                "overall_similarity": 0.41,
                "text_similarity": 0.33,
                "domain_match": False,
                "host_match": False,
                "content_sha256": "deadbeef",
                "evidence_codes": ["brand_token_domain_mismatch"],
            },
            {
                "reference_id": "rag_1_y",
                "official_url": "https://dvolt.ir/",
                "retrieval_score": 0.7312,
                "reference_quality": 0.30,
                "overall_similarity": 0.22,
                "domain_match": False,
                "evidence_codes": [],
            },
        ],
    )
    review = AgentClient._parse_result("abc123", result)
    summary = review.audit_summary()
    assert summary["references_retrieved"] == 2
    assert [m["official_url"] for m in summary["reference_matches"]] == [
        "https://digikala.com/",
        "https://dvolt.ir/",
    ]
    assert summary["reference_matches"][0]["retrieval_score"] == 0.7461
    assert summary["reference_matches"][0]["evidence_codes"] == ["brand_token_domain_mismatch"]
    # The compact view must not forward raw/unbounded fields like content_sha256.
    assert "content_sha256" not in summary["reference_matches"][0]


def test_absent_reference_matches_mean_zero_retrieved():
    review = AgentClient._parse_result("abc123", completed_result())
    summary = review.audit_summary()
    assert summary["references_retrieved"] == 0
    assert summary["reference_matches"] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("detail,expected", [
    ("reference_service_http_500", "reference_service_http_500"),
    ("reference_service_timeout", "reference_service_timeout"),
    ("arbitrary provider text", "reference_retrieval_http_503"),
])
async def test_detector_preserves_only_safe_reference_failure_codes(detail, expected):
    client = AgentClient("https://review.example")
    client._client = httpx.AsyncClient(base_url="https://review.example", transport=httpx.MockTransport(
        lambda _: httpx.Response(503, json={"detail": detail}),
    ))
    try:
        with pytest.raises(AgentServiceError, match=rf"^{expected}$"):
            await client.retrieve_references(suspect_url="https://suspect.example/", suspect_html="<p>fixture</p>")
    finally:
        await client.close()


@pytest.mark.asyncio
async def test_low_confidence_with_rag_and_analyst_failures_is_reported_as_incomplete(tmp_path, monkeypatch):
    from unittest.mock import AsyncMock

    from persianphish_detector.agent import AgentServiceError

    agent = FakeAgent(replace(review("suspicious", 0.5, 0.41), reasons=[
        "agent_unavailable_or_invalid", "analyst_timeouterror", "reference_service_unavailable",
    ]))
    agent.retrieve_references = AsyncMock(side_effect=AgentServiceError("reference_retrieval_http_503"))
    detector = make_detector(tmp_path, usable_evidence(), Verdict.SUSPICIOUS, agent)
    detector.jev = SimpleNamespace(score=AsyncMock(return_value=JevFinding(
        ok=True, phishing_score=0.06, confidence=0.62, label="legitimate",
    )))
    monkeypatch.setattr(orchestrator_module, "extract_features", lambda *_: base_features())
    result = await detector.detect("https://snapp.market/", pipeline=("decision", "rag", "agent"))
    assert result.verdict == Verdict.SUSPICIOUS
    assert "jev_gate_confidence" in result.reason_codes
    assert "agent_review_unavailable" in result.reason_codes
    assert "agent_review_completed" not in result.reason_codes
    assert result.evidence_summary["agent_review"]["error_code"] == "analyst_timeouterror"
    steps = result.evidence_summary["pipeline"]
    assert [(step["status"], step.get("error_code")) for step in steps] == [
        ("completed", None),
        ("unavailable", "reference_retrieval_http_503"),
        ("unavailable", "analyst_timeouterror"),
    ]


@pytest.mark.asyncio
@pytest.mark.parametrize("risk,confidence,label,observed_risk,override,clears,gate", [
    (0.05, 0.80, "legitimate", False, None, True, None),
    (0.02, 0.96, "legitimate", False, None, True, None),
    (0.05, 0.60, "legitimate", False, None, False, "jev_gate_confidence"),
    (0.06, 0.95, "legitimate", False, None, False, "jev_gate_legitimate_risk"),
    (0.01, 0.95, "suspicious", False, None, False, "jev_gate_label"),
    (0.01, 0.95, "legitimate", True, None, False, "jev_gate_observed_risk"),
    (0.07, 0.79, "legitimate", False, {}, True, None),
    (0.07, 0.79, "legitimate", False, {"allow_early_clear": False}, False, "jev_gate_early_clear_disabled"),
])
async def test_remote_decision_short_circuits_only_when_all_clearance_checks_pass(
    tmp_path, monkeypatch, risk, confidence, label, observed_risk, override, clears, gate,
):
    from unittest.mock import AsyncMock

    from persianphish_detector.jev import DecisionThresholds

    agent = FakeAgent(review("suspicious", 0.5, 0.41))
    agent.retrieve_references = AsyncMock(return_value=([], []))
    detector = make_detector(tmp_path, usable_evidence(), Verdict.SUSPICIOUS, agent)
    detector.jev = SimpleNamespace(score=AsyncMock(return_value=JevFinding(
        ok=True, phishing_score=risk, confidence=confidence, label=label,
    )))
    features = base_features()
    if observed_risk:
        features["external_form_action_count"] = 1
    monkeypatch.setattr(orchestrator_module, "extract_features", lambda *_: features)
    thresholds = None if override is None else DecisionThresholds(
        escalation_risk=0.20, minimum_confidence=0.75, legitimate_max_risk=0.08, **override,
    )
    result = await detector.detect(
        "https://suspect.example/", pipeline=("decision", "rag", "agent"), decision_thresholds=thresholds,
    )
    assert result.verdict == (Verdict.LEGITIMATE if clears else Verdict.SUSPICIOUS)
    assert agent.retrieve_references.await_count == len(agent.calls) == (0 if clears else 1)
    assert [step["status"] for step in result.evidence_summary["pipeline"]] == (
        ["completed", "skipped", "skipped"] if clears else ["completed", "completed", "completed"]
    )
    assert (gate or "jev_short_circuit_legit") in result.reason_codes


@pytest.mark.asyncio
@pytest.mark.parametrize("stages", [
    ("rf",), ("decision",), ("rag",), ("agent",),
    ("decision", "rag", "rf", "agent"), ("agent", "rf", "decision", "rag"),
])
async def test_explicit_pipeline_runs_selected_stages_in_order(monkeypatch, tmp_path, stages):
    from unittest.mock import AsyncMock

    calls = []
    agent = FakeAgent(review("suspicious", 0.5, 0.49))
    ref = {"reference_id": "rag_example", "html": "<html>reference</html>"}

    async def retrieve(**kwargs):
        calls.append("rag")
        return [ref], [{"official_url": "https://official.example/"}]

    async def agent_review(**kwargs):
        calls.append("agent")
        assert kwargs["automatic_references"] is False
        expected = [ref] if "rag" in stages[:stages.index("agent")] else []
        assert kwargs["references"] == expected
        return agent.result

    async def decision(*args):
        calls.append("decision")
        return Verdict.SUSPICIOUS, {"status": "completed", "risk": 0.4}, []

    detector = make_detector(tmp_path, usable_evidence(), Verdict.SUSPICIOUS, agent)
    score_fast = detector._score_fast

    def rf(*args):
        calls.append("rf")
        return score_fast(*args)

    monkeypatch.setattr(agent, "retrieve_references", retrieve, raising=False)
    monkeypatch.setattr(agent, "review", agent_review)
    monkeypatch.setattr(detector, "_score_fast", rf)
    monkeypatch.setattr(detector, "_pipeline_decision", decision)
    monkeypatch.setattr(orchestrator_module, "collect_domain_facts", AsyncMock(return_value=DomainFacts()))
    monkeypatch.setattr(orchestrator_module, "extract_features", lambda *_: base_features())

    progress = []
    result = await detector.detect("https://suspect.example/", pipeline=stages, on_progress=progress.append)
    assert result.verdict == Verdict.SUSPICIOUS
    assert calls == list(stages)
    assert [step["status"] for step in result.evidence_summary["pipeline"]] == ["completed"] * len(stages)
    assert progress[:2] == [
        {"type": "stage", "stage": "crawl", "status": "started"},
        {"type": "stage", "stage": "crawl", "status": "completed"},
    ]
    assert [(event["stage"], event["status"]) for event in progress[2:]] == [
        (stage, phase) for stage in stages for phase in ("started", "completed")
    ]
    assert "<html" not in json.dumps(result.to_dict()).lower()


@pytest.mark.asyncio
async def test_explicit_pipeline_skips_following_steps_on_rf_flag_and_all_steps_on_403(monkeypatch, tmp_path):
    from unittest.mock import AsyncMock

    agent = FakeAgent(review("suspicious", 0.5, 0.49))
    evidence = usable_evidence()
    detector = make_detector(tmp_path, evidence, Verdict.PHISHING, agent)
    monkeypatch.setattr(orchestrator_module, "collect_domain_facts", AsyncMock(return_value=DomainFacts()))
    monkeypatch.setattr(orchestrator_module, "extract_features", lambda *_: base_features())
    pipeline = ("rf", "decision", "rag", "agent")
    flagged = await detector.detect("https://suspect.example/", pipeline=pipeline)
    assert flagged.verdict == Verdict.PHISHING
    assert flagged.stage == "rf"
    assert [s["status"] for s in flagged.evidence_summary["pipeline"]] == ["completed", "skipped", "skipped", "skipped"]

    detector.http.evidence = replace(evidence, status=CrawlStatus.BLOCKED, http_status=403)
    failed = await detector.detect("https://suspect.example/", pipeline=pipeline)
    assert failed.verdict == Verdict.CRAWL_FAILED
    assert [s["status"] for s in failed.evidence_summary["pipeline"]] == ["skipped"] * 4
    assert not agent.calls
