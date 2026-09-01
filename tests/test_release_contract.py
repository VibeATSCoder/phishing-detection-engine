import json
import re
from pathlib import Path

from persianphish_detector import __version__


ROOT = Path(__file__).resolve().parents[1]


def test_component_versions_and_compose_are_synchronized():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_version = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, flags=re.MULTILINE)
    assert project_version and project_version.group(1) == __version__ == "3.1.0"

    contract = json.loads((ROOT / "deploy" / "COMPATIBILITY.json").read_text(encoding="utf-8"))
    assert contract["components"]["detector"]["version"] == "3.1.0"
    assert contract["components"]["extension"]["version"] == "3.4.0"
    assert contract["components"]["reviewer"]["version"] == "1.3.0"
    # Reference retrieval is optional: the reviewer runs without it and simply
    # supplies no references, so a deployment lacking it is degraded rather than
    # broken. The flag is asserted so that status stays deliberate.
    assert contract["components"]["rag"]["version"] == "0.1.0"
    assert contract["components"]["rag"]["optional"] is True
    assert contract["contracts"]["reviewer_to_rag"] == "POST /v1/references"
    assert contract["contracts"]["verdicts"] == [
        "legitimate", "phishing", "suspicious", "crawl_failed"
    ]

    compose = (ROOT / "deploy" / "compose.yaml").read_text(encoding="utf-8")
    assert "phishing-detection-engine:3.1.0-integrated" in compose
    assert "agentic-phishing-review:1.3.0-integrated" in compose
    assert "${AGENT_REVIEW_CONTEXT:-../../agentic-phishing-review}" in compose


def test_clean_docker_build_does_not_require_runtime_database():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY var" not in dockerfile
    assert 'ARG APP_VERSION=3.1.0' in dockerfile
