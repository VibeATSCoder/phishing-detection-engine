from pathlib import Path

from fastapi.testclient import TestClient

from persianphish_detector import __version__
from persianphish_detector.api import create_app
from persianphish_detector.config import DetectorConfig


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
    assert response.json()["service_version"] == __version__ == "3.4.1"


def test_ready_exposes_version_without_claiming_missing_models_are_ready(tmp_path: Path):
    with TestClient(create_app(config(tmp_path))) as client:
        response = client.get("/ready")
    assert response.status_code == 503
    assert response.json()["service_version"] == "3.4.1"
    assert response.json()["ready"] is False
