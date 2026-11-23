from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

from persianphish_detector import orchestrator
from persianphish_detector.api import create_app
from persianphish_detector.config import DetectorConfig
from persianphish_detector.jev import DecisionThresholds, JevFinding
from persianphish_detector.orchestrator import Detector
from persianphish_detector.trusted_urls import TrustedURLStore
from persianphish_detector.types import CrawlEvidence, CrawlStatus, Verdict


URL = "https://shop.example/"
PIPELINE = ("decision", "rag", "agent")


@pytest.fixture
def fixture_detector(tmp_path, monkeypatch):
    config = DetectorConfig(
        tmp_path / "model", tmp_path / "intel.sqlite", tmp_path / "review.sqlite", tmp_path / "results",
        use_browser=False, jev_base_url="https://decision.example/v1", jev_model="decision-fixture",
    )
    detector = Detector(config)
    detector.jev.score = AsyncMock(return_value=JevFinding(
        ok=True, label="legitimate", phishing_score=0.02, confidence=0.96,
    ))
    detector.http.fetch = AsyncMock(side_effect=lambda url: CrawlEvidence(
        target_url=url, final_url=url, status=CrawlStatus.OK, http_status=200,
        html="<html><body>A known shop sells groceries.</body></html>", redirect_chain=[url],
    ))
    features = {
        "external_form_action_count": 0, "suspicious_token_count": 0, "password_input_count": 0,
        "title_domain_token_overlap": 1, "unicode_confusable_count": 0, "cross_domain_redirect_count": 0,
    }
    monkeypatch.setattr(orchestrator, "extract_features", lambda *_: features)
    monkeypatch.setattr(orchestrator, "jev_structure", lambda *_: {})
    return detector


@pytest.mark.parametrize("url", [
    "https://www.google.com/",
    "https://www.google.com/search?client=chrome&q=%D8%AA%D8%B3%D8%AA",
    "https://www.digikala.com/search/category/?page=2",
])
async def test_ordered_allowlist_obeys_threat_intelligence_and_stage_contract(fixture_detector, url):
    detector = fixture_detector
    result = await detector.detect(url, pipeline=PIPELINE)
    assert result.verdict == Verdict.LEGITIMATE
    assert result.stage == "allowlist"
    assert result.crawl_status == CrawlStatus.SKIPPED
    assert result.evidence_summary["pipeline"] == [
        {"stage": stage, "status": "skipped"} for stage in PIPELINE
    ]
    detector.intel.add(url, verdict="phishing", source="test-feed")
    blocked = await detector.detect(url, pipeline=PIPELINE)
    assert blocked.verdict == Verdict.PHISHING
    assert blocked.stage == "reputation"
    assert blocked.evidence_summary["pipeline"] == result.evidence_summary["pipeline"]
    detector.http.fetch.assert_not_awaited()
    detector.jev.score.assert_not_awaited()


async def test_exact_url_cache_persists_and_partitions_by_policy(fixture_detector):
    detector = fixture_detector
    first = await detector.detect(URL, pipeline=PIPELINE)
    detector.trust = TrustedURLStore(detector.config.intel_db_path)
    cached = await detector.detect(URL, pipeline=PIPELINE)
    assert first.stage == "decision" and "trusted_url_cache_stored" in first.reason_codes
    assert cached.stage == "trusted_url_cache" and cached.crawl_status == CrawlStatus.SKIPPED
    assert cached.request_id != first.request_id
    assert cached.risk_score == first.risk_score == 0.02
    assert cached.evidence_summary["trusted_url"] == first.evidence_summary["trusted_url"]
    assert cached.evidence_summary["trusted_url"]["confidence"] == 0.96
    assert detector.http.fetch.await_count == detector.jev.score.await_count == 1

    stricter = DecisionThresholds(escalation_risk=0.20, minimum_confidence=0.99, legitimate_max_risk=0.02)
    strict_result = await detector.detect(URL, pipeline=PIPELINE, decision_thresholds=stricter)
    assert strict_result.verdict == Verdict.SUSPICIOUS
    assert strict_result.stage != "trusted_url_cache"
    await detector.detect(URL + "catalog", pipeline=PIPELINE)
    await detector.detect(URL + "?ref=1", pipeline=PIPELINE)
    await detector.detect(URL, pipeline=PIPELINE, use_trusted_urls=False)
    assert detector.http.fetch.await_count == detector.jev.score.await_count == 5
    detector.intel.add(URL, verdict="phishing", source="new-indicator")
    assert (await detector.detect(URL, pipeline=PIPELINE)).verdict == Verdict.PHISHING
    assert detector.http.fetch.await_count == 5


def test_detector_api_can_bypass_a_recent_trusted_result(fixture_detector):
    detector = fixture_detector
    app = create_app(detector.config)
    with TestClient(app) as client:
        app.state.detector = detector
        url_data = {"url": URL, "pipeline": list(PIPELINE)}
        first = client.post("/v1/detect", json=url_data).json()
        response = client.post("/v1/detect", json=url_data, headers={"Accept": "application/x-ndjson"})
        assert len(response.text.splitlines()) == 1
        import json
        cached = json.loads(response.text)["result"]
        fresh = client.post("/v1/detect", json={**url_data, "use_trusted_urls": False}).json()
        assert first["stage"] == fresh["stage"] == "decision"
        assert cached["stage"] == "trusted_url_cache"
        assert cached["crawl_status"] == "skipped"
        assert detector.http.fetch.await_count == 2


async def test_rag_candidates_do_not_clear_without_first_party_crawl(fixture_detector, monkeypatch):
    detector = fixture_detector
    from persianphish_detector import trusted_urls

    monkeypatch.setattr(trusted_urls, "time", SimpleNamespace(time=lambda: 1000))
    count = detector.trust.replace_references([URL, "https://no-match.example/", "http://blocked.example/"])
    assert count == 2
    first = await detector.detect(URL, pipeline=PIPELINE)
    assert first.stage == "decision"
    record = first.evidence_summary["trusted_url"]
    assert record["source"] == "rag_reference_verified"
    assert record["expires_at"] == 1000 + detector.config.trusted_rag_url_ttl_s
    detector.trust.replace_references(["https://no-match.example/"])
    refreshed = await detector.detect(URL, pipeline=PIPELINE)
    assert refreshed.stage == "decision"
    assert refreshed.evidence_summary["trusted_url"]["source"] == "high_confidence_decision"
    assert refreshed.evidence_summary["trusted_url"]["expires_at"] == 1000 + detector.config.trusted_url_ttl_s
    monkeypatch.setattr(trusted_urls, "time", SimpleNamespace(time=lambda: 1000 + detector.config.trusted_url_ttl_s))
    expired = await detector.detect(URL, pipeline=PIPELINE)
    assert expired.stage == "decision"
    assert detector.http.fetch.await_count == 3


@pytest.mark.parametrize("condition", ["confidence", "risk", "redirect", "blocked", "query", "fragment", "caller_html"])
async def test_ineligible_results_do_not_enter_the_trusted_cache(fixture_detector, condition, monkeypatch):
    detector = fixture_detector
    url = URL
    evidence = None
    first_find = detector.jev.score.return_value
    if condition == "confidence":
        detector.jev.score.return_value = replace(first_find, confidence=0.85)
    elif condition == "risk":
        detector.jev.score.return_value = replace(first_find, phishing_score=0.04)
    elif condition in {"redirect", "blocked"}:
        detector.http.fetch.side_effect = lambda url: CrawlEvidence(
            target_url=url, final_url="https://other.example/" if condition == "redirect" else url,
            status=CrawlStatus.OK if condition == "redirect" else CrawlStatus.BLOCKED,
            http_status=200 if condition == "redirect" else 403, html="<body>Fixture</body>",
            redirect_chain=[url, "https://other.example/"] if condition == "redirect" else [url],
        )
    elif condition == "query":
        url += "?destination=elsewhere"
    elif condition == "fragment":
        url += "#other-page"
    elif condition == "caller_html":
        evidence = {"final_url": url, "http_status": 200, "dom_html": "<body>Test</body>"}
        monkeypatch.setattr(orchestrator, "resolve_public_addresses", lambda *_: ["93.184.216.34"])
        monkeypatch.setattr(orchestrator, "from_browser_payload", lambda *_: CrawlEvidence(
            target_url=url, final_url=url, status=CrawlStatus.OK, http_status=200,
            html="<body>Caller content</body>",
        ))
    first = await detector.detect(url, browser_evidence=evidence, pipeline=PIPELINE)
    second = await detector.detect(url, browser_evidence=evidence, pipeline=PIPELINE)
    assert "trusted_url" not in first.evidence_summary
    assert second.stage != "trusted_url_cache"
    if condition == "blocked":
        assert second.verdict == Verdict.CRAWL_FAILED
        detector.jev.score.assert_not_awaited()
    elif condition in {"confidence", "risk", "query", "fragment"}:
        assert second.stage == "scan_cache"
        assert detector.jev.score.await_count == 1
    else:
        assert second.stage != "scan_cache"
        assert detector.jev.score.await_count == 2


async def test_completed_suspicious_scan_reuses_exact_policy_until_expiry(fixture_detector, monkeypatch):
    from persianphish_detector import trusted_urls

    now = [1000]
    monkeypatch.setattr(trusted_urls, "time", SimpleNamespace(time=lambda: now[0]))
    detector = fixture_detector
    url = URL + "product?size=large"
    pipeline = ("decision",)
    thresholds = DecisionThresholds(escalation_risk=0.5, minimum_confidence=0.5, legitimate_max_risk=0.4)
    finding = replace(detector.jev.score.return_value, phishing_score=0.2, confidence=0.42)
    detector.jev.score.return_value = finding

    first = await detector.detect(url, pipeline=pipeline, decision_thresholds=thresholds)
    detector.trust = TrustedURLStore(detector.config.intel_db_path)
    now[0] += 86399
    detector.jev.score.return_value = replace(finding, phishing_score=0.1, confidence=0.75)
    hit = await detector.detect(url, pipeline=pipeline, decision_thresholds=thresholds)
    assert hit.verdict == first.verdict == Verdict.SUSPICIOUS
    assert hit.risk_score == first.risk_score == 0.2
    assert hit.request_id != first.request_id
    assert hit.crawl_status == CrawlStatus.SKIPPED and hit.stage == "scan_cache"
    assert hit.evidence_summary["pipeline"] == [{"stage": "decision", "status": "skipped"}]
    assert hit.evidence_summary["scan_cache"] == {
        "original_request_id": first.request_id, "stored_at": 1000, "expires_at": 87400,
    }
    assert hit.evidence_summary["jev"] == first.evidence_summary["jev"]
    assert detector.jev.score.await_count == 1

    stricter = thresholds.model_copy(update={"minimum_confidence": 0.8})
    changed = await detector.detect(url, pipeline=pipeline, decision_thresholds=stricter)
    assert changed.stage != "scan_cache"
    other = await detector.detect(url.replace("large", "small"), pipeline=pipeline, decision_thresholds=thresholds)
    assert other.stage != "scan_cache"
    now[0] += 1
    refreshed = await detector.detect(url, pipeline=pipeline, decision_thresholds=thresholds)
    assert refreshed.stage == "decision" and refreshed.verdict == Verdict.LEGITIMATE
    assert detector.jev.score.await_count == 4
    detector.intel.add(url, verdict="phishing", source="test-feed")
    blocked = await detector.detect(url, pipeline=pipeline, decision_thresholds=thresholds)
    assert blocked.stage == "reputation" and blocked.verdict == Verdict.PHISHING


async def test_failed_provider_is_not_replayed(fixture_detector):
    detector = fixture_detector
    detector.jev.score.return_value = JevFinding(error="provider_timeout")
    for _ in range(2):
        result = await detector.detect(URL, pipeline=("decision",))
        assert result.evidence_summary["pipeline"][0]["status"] == "unavailable"
    assert detector.jev.score.await_count == 2


async def test_below_confidence_and_observed_signals_explain_decision(fixture_detector):
    detector = fixture_detector
    features = orchestrator.extract_features()
    features.update(password_input_count=1, title_domain_token_overlap=0)
    detector.jev.score.return_value = replace(detector.jev.score.return_value, phishing_score=0.2, confidence=0.42)
    # The configured risk limits pass. Both independent gates still route to review.
    thresholds = DecisionThresholds(escalation_risk=0.5, minimum_confidence=0.5, legitimate_max_risk=0.4)
    result = await detector.detect(URL, pipeline=("decision",), decision_thresholds=thresholds)
    assert result.verdict == Verdict.SUSPICIOUS
    decision = result.evidence_summary["jev"]
    assert decision["gates"] == ["jev_gate_observed_risk", "jev_gate_confidence"]
    assert decision["observed_signals"] == ["password_title_mismatch"]
    assert "jev_observed_password_title_mismatch" in result.reason_codes
