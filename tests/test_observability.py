from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from persianphish_detector import observability
from persianphish_detector.api import create_app
from persianphish_detector.config import DetectorConfig
from persianphish_detector.observability import (
    METRICS,
    record_detection,
    set_build_info,
    span,
    telemetry_canonical_url,
    url_digest,
    url_labels,
)
from persianphish_detector.types import CrawlStatus, DetectionResult, Verdict

# The module degrades to no-ops without the observability extra, and the service
# must keep working that way. These cases inspect metric *content*, which only
# exists when prometheus_client is installed, so they are skipped rather than
# weakened into assertions that would pass either way.
needs_prometheus = pytest.mark.skipif(
    not observability.PROMETHEUS_AVAILABLE, reason="requires the observability extra"
)


# Golden digests shared with the reviewer, the monitor, and the extension's
# diagnostics.js. A change here silently breaks cross-service correlation
# rather than failing loudly, so the values are pinned.
GOLDEN_DIGESTS = {
    "https://Example.COM:443/Login?b=2&a=1#frag": "f5e1bdeacac536ca",
    "https://example.com/Login?a=1&b=2": "f5e1bdeacac536ca",
    "http://example.com:80/": "2a1b402420ef4657",
    "https://example.com": "0f115db062b7c0dd",
    "https://sub.example.co.uk/path?z=9&a=0": "c368c4f6ed377c46",
}


def config(tmp_path: Path) -> DetectorConfig:
    return DetectorConfig(
        artifact_path=tmp_path / "missing.joblib",
        intel_db_path=tmp_path / "intel.sqlite3",
        review_db_path=tmp_path / "review.sqlite3",
        result_dir=tmp_path / "results",
        use_browser=False,
    )


def series_for(family: str) -> list[str]:
    body = METRICS.render().decode("utf-8")
    return [line for line in body.splitlines() if line.startswith(family)]


def result(verdict=Verdict.SUSPICIOUS, stage="model", url="https://example.com/login"):
    return DetectionResult(
        request_id="abc123",
        url=url,
        final_url=url,
        verdict=verdict,
        risk_score=0.5,
        stage=stage,
        crawl_status=CrawlStatus.OK,
        reason_codes=["model_uncertain"],
        model_scores={"rf": 0.44, "tcn": 0.61, "combined": 0.5},
        latency_ms={"total": 1200.0, "crawl": 800.0, "agent": 0.0},
    )


def test_digests_match_the_cross_service_contract():
    for url, expected in GOLDEN_DIGESTS.items():
        assert url_digest(url) == expected, f"digest drifted for {url}"


def test_canonicalization_rules():
    assert (
        telemetry_canonical_url("https://Example.COM:443/Login?b=2&a=1#frag")
        == "https://example.com/Login?a=1&b=2"
    )
    assert telemetry_canonical_url("http://example.com:80/") == "http://example.com/"
    assert telemetry_canonical_url("https://example.com:8443/x") == "https://example.com:8443/x"
    # An empty path must normalize to "/" so it matches the explicit form.
    assert telemetry_canonical_url("https://example.com") == telemetry_canonical_url(
        "https://example.com/"
    )


def test_url_labels_do_not_leak_path_or_query():
    labels = url_labels("https://victim.example/reset?token=super-secret")
    assert set(labels) == {"url.digest", "url.registrable_domain"}
    assert labels["url.registrable_domain"] == "victim.example"
    for value in labels.values():
        assert "super-secret" not in value
        assert "reset" not in value


@needs_prometheus
def test_record_detection_counts_every_verdict():
    for verdict in (
        Verdict.LEGITIMATE,
        Verdict.PHISHING,
        Verdict.SUSPICIOUS,
        Verdict.CRAWL_FAILED,
    ):
        record_detection(result(verdict=verdict))

    body = "\n".join(series_for("ppd_detections_total"))
    for verdict in ("legitimate", "phishing", "suspicious", "crawl_failed"):
        assert f'verdict="{verdict}"' in body


@needs_prometheus
def test_record_detection_splits_total_from_per_stage_latency():
    record_detection(result())
    assert any('verdict="suspicious"' in line for line in series_for("ppd_detection_duration_seconds_count"))
    stage_series = "\n".join(series_for("ppd_stage_duration_seconds_count"))
    assert 'stage="crawl"' in stage_series
    # "total" belongs to the detection histogram, never to the per-stage one.
    assert 'stage="total"' not in stage_series


@needs_prometheus
def test_record_detection_tolerates_missing_scores():
    """Fast-path exits carry None scores; they must not raise or be recorded."""
    partial = result(verdict=Verdict.PHISHING, stage="reputation")
    partial.model_scores = {"rf": None, "tcn": None}
    partial.latency_ms = {"total": 3.0}
    record_detection(partial)
    assert any('stage="reputation"' in line for line in series_for("ppd_detections_total"))


@needs_prometheus
def test_metrics_endpoint_serves_prometheus_text(tmp_path: Path):
    with TestClient(create_app(config(tmp_path))) as client:
        response = client.get("/metrics")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/plain")
    assert "ppd_detections_total" in response.text


def test_metrics_endpoint_is_exempt_from_the_api_key(tmp_path: Path):
    """Prometheus scrapes without credentials, like /health and /ready."""
    guarded = DetectorConfig(
        artifact_path=tmp_path / "missing.joblib",
        intel_db_path=tmp_path / "intel.sqlite3",
        review_db_path=tmp_path / "review.sqlite3",
        result_dir=tmp_path / "results",
        use_browser=False,
        api_key="secret-key",
    )
    with TestClient(create_app(guarded)) as client:
        assert client.get("/metrics").status_code == 200
        assert client.get("/health").status_code == 200
        assert client.get("/v1/review").status_code == 401


@needs_prometheus
def test_http_route_label_is_templated_not_per_request(tmp_path: Path):
    with TestClient(create_app(config(tmp_path))) as client:
        for request_id in ("aaaa1111", "bbbb2222", "cccc3333"):
            client.get(f"/v1/detect/{request_id}")

    lines = series_for("ppd_http_requests_total")
    assert any("/v1/detect/{request_id}" in line for line in lines)
    for request_id in ("aaaa1111", "bbbb2222", "cccc3333"):
        assert not any(request_id in line for line in lines)


@needs_prometheus
def test_build_info_publishes_the_artifact_production_flag():
    set_build_info("3.1.0", "v3-tcn-test", False)
    lines = series_for("ppd_build_info")
    assert any('artifact_production_ready="false"' in line for line in lines)
    assert any('model_version="v3-tcn-test"' in line for line in lines)


def test_span_is_usable_whether_or_not_opentelemetry_is_installed():
    with span("detector.test", **url_labels("https://example.com/")) as current:
        if observability.OTEL_AVAILABLE:
            assert current is not None
        else:
            assert current is None


def test_span_records_an_error_without_swallowing_it():
    try:
        with span("detector.boom"):
            raise ValueError("boom")
    except ValueError as exc:
        assert str(exc) == "boom"
    else:  # pragma: no cover
        raise AssertionError("span swallowed an exception")


def test_configure_tracing_is_inert_without_an_endpoint(monkeypatch):
    monkeypatch.delenv("OTEL_EXPORTER_OTLP_ENDPOINT", raising=False)
    assert observability.configure_tracing("3.1.0") is False
