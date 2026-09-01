from pathlib import Path

from fastapi.testclient import TestClient

from persianphish_detector.api import create_app
from persianphish_detector.config import DetectorConfig
from persianphish_detector.evidence_codes import Severity, Source, derive_evidence


def codes(items):
    return [item["code"] for item in items]


def config(tmp_path: Path) -> DetectorConfig:
    return DetectorConfig(
        artifact_path=tmp_path / "missing.joblib",
        intel_db_path=tmp_path / "intel.sqlite3",
        review_db_path=tmp_path / "review.sqlite3",
        result_dir=tmp_path / "results",
        use_browser=False,
    )


def test_url_features_become_evidence():
    items = derive_evidence(
        {"has_idn_or_punycode": 1, "suspicious_token_count": 3, "subdomain_count": 6}
    )
    assert "punycode_hostname" in codes(items)
    assert "trust_word_in_hostname" in codes(items)
    assert "excessive_subdomains" in codes(items)


def test_features_at_or_below_threshold_produce_nothing():
    """A feature must exceed its threshold; equality is not an observation."""
    assert derive_evidence({"has_idn_or_punycode": 0, "suspicious_token_count": 0}) == []
    # subdomain_count's threshold is 3, so exactly 3 must stay silent.
    assert "excessive_subdomains" not in codes(derive_evidence({"subdomain_count": 3}))
    assert "excessive_subdomains" in codes(derive_evidence({"subdomain_count": 4}))


def test_inverted_rule_reports_missing_https_not_present_https():
    assert "insecure_transport" in codes(derive_evidence({"is_https": 0}))
    assert "insecure_transport" not in codes(derive_evidence({"is_https": 1}))


def test_two_features_implying_one_observation_are_deduplicated():
    """eval() and atob() both mean an obfuscated script; report it once."""
    items = derive_evidence({"eval_count": 3, "atob_count": 2})
    assert codes(items).count("obfuscated_script") == 1


def test_agent_codes_are_merged_and_deduplicated_against_local_ones():
    items = derive_evidence(
        {"has_idn_or_punycode": 1},
        agent_codes=["punycode_hostname", "qr_code", "qr_code"],
    )
    assert codes(items).count("punycode_hostname") == 1
    assert codes(items).count("qr_code") == 1
    # The locally derived one wins, so its source is preserved.
    punycode = next(item for item in items if item["code"] == "punycode_hostname")
    assert punycode["source"] == Source.URL


def test_unknown_agent_code_still_surfaces_at_low_severity():
    """A reviewer code added after this release must not silently vanish."""
    items = derive_evidence(agent_codes=["some_future_code"])
    assert items == [
        {"code": "some_future_code", "source": Source.AGENT, "severity": Severity.LOW}
    ]


def test_items_are_ordered_most_severe_first():
    items = derive_evidence(
        {"has_idn_or_punycode": 1, "subdomain_count": 6, "long_random_token_count": 1}
    )
    rank = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    order = [rank[item["severity"]] for item in items]
    assert order == sorted(order)


def test_intel_match_and_failed_crawl_are_reported():
    class Match:
        verdict = "phishing"

    assert "known_phishing_indicator" in codes(derive_evidence(intel_match=Match()))
    assert "page_not_observed" in codes(derive_evidence(crawl_status="blocked"))
    # A usable crawl is not itself an observation.
    assert "page_not_observed" not in codes(derive_evidence(crawl_status="ok"))


def test_benign_intel_match_is_not_evidence_of_phishing():
    class Benign:
        verdict = "benign"

    assert "known_phishing_indicator" not in codes(derive_evidence(intel_match=Benign()))


def test_non_numeric_feature_values_are_ignored_not_raised():
    assert derive_evidence({"has_idn_or_punycode": "unexpected"}) == []
    assert derive_evidence({"suspicious_token_count": None}) == []


def test_detect_response_exposes_evidence_alongside_reason_codes(tmp_path: Path):
    """The API contract: `evidence` is additive, `reason_codes` is unchanged."""
    with TestClient(create_app(config(tmp_path))) as client:
        response = client.post("/v1/detect", json={"url": "https://198.51.100.9/login"})
    assert response.status_code == 200
    body = response.json()
    assert "evidence" in body and isinstance(body["evidence"], list)
    assert "reason_codes" in body and isinstance(body["reason_codes"], list)
    for item in body["evidence"]:
        assert set(item) == {"code", "source", "severity"}
        assert item["severity"] in {Severity.HIGH, Severity.MEDIUM, Severity.LOW}


def test_evidence_never_carries_the_url_or_free_text(tmp_path: Path):
    """Evidence items are codes, not prose, and must not echo the address."""
    with TestClient(create_app(config(tmp_path))) as client:
        response = client.post(
            "/v1/detect", json={"url": "https://198.51.100.9/login?token=secret-value"}
        )
    for item in response.json()["evidence"]:
        for value in item.values():
            assert "secret-value" not in value
            assert "198.51.100.9" not in value
