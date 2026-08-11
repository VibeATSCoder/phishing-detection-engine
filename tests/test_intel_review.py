from pathlib import Path

from persianphish_detector.intel import IntelStore
from persianphish_detector.review import ReviewStore


def test_exact_url_indicator_does_not_blacklist_unrelated_path(tmp_path: Path):
    store = IntelStore(tmp_path / "intel.sqlite3")
    store.add("https://compromised.example/phish", verdict="phishing", source="test", scope="url")
    assert store.lookup("https://compromised.example/phish") is not None
    assert store.lookup("https://compromised.example/healthy") is None


def test_verified_benign_csv_import_is_host_scoped(tmp_path: Path):
    source = tmp_path / "features.csv"
    source.write_text(
        "sample_id,url,label,label_quality,capture_date,quality_score\n"
        "one,https://soft98.ir/,0,verified_legitimate,20260131,0.96\n"
        "two,https://bad.example/,1,generated_phishing,20260131,1.0\n",
        encoding="utf-8",
    )
    store = IntelStore(tmp_path / "intel.sqlite3")
    assert store.import_verified_benign(source) == 1
    match = store.lookup("https://soft98.ir/downloads")
    assert match is not None
    assert match.verdict == "benign"
    assert match.scope == "host"
    assert store.lookup("https://sub.soft98.ir/") is None


def test_review_round_trip(tmp_path: Path):
    store = ReviewStore(tmp_path / "review.sqlite3")
    store.enqueue(
        request_id="abc123",
        url="https://example.com/",
        verdict="suspicious",
        risk_score=0.55,
        reason_codes=["model_disagreement"],
        evidence={"html": "secret raw html", "http_status": 200},
    )
    pending = store.pending()
    assert len(pending) == 1
    assert "secret raw html" not in pending[0]["evidence_json"]
    assert store.resolve("abc123", "legitimate", "reviewed")
    assert store.pending() == []
    destination = tmp_path / "resolved.csv"
    assert store.export_resolved(destination) == 1
    assert "abc123" in destination.read_text(encoding="utf-8")
