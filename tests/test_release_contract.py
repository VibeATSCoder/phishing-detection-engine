import json
import re
from pathlib import Path

import pytest

from persianphish_detector import __version__


ROOT = Path(__file__).resolve().parents[1]


def test_component_versions_and_compose_are_synchronized():
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    project_version = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, flags=re.MULTILINE)
    assert project_version and project_version.group(1) == __version__ == "3.8.0"

    contract = json.loads((ROOT / "deploy" / "COMPATIBILITY.json").read_text(encoding="utf-8"))
    assert contract["components"]["detector"]["version"] == "3.8.0"
    # Versioned independently of the detector; the manifest is the authority
    # and test_recorded_extension_version_matches_the_extension_repository
    # compares against it.
    assert contract["components"]["extension"]["version"] == "3.5.0"
    assert contract["components"]["reviewer"]["version"] == "1.10.0"
    # Reference retrieval is optional: the reviewer runs without it and simply
    # supplies no references, so a deployment lacking it is degraded rather than
    # broken. The flag is asserted so that status stays deliberate.
    assert contract["components"]["rag"]["version"] == "1.0.2"
    assert contract["components"]["rag"]["optional"] is True
    assert contract["contracts"]["reviewer_to_rag"] == "POST /v1/references"
    assert contract["contracts"]["verdicts"] == [
        "legitimate", "phishing", "suspicious", "crawl_failed"
    ]

    compose = (ROOT / "deploy" / "compose.yaml").read_text(encoding="utf-8")
    assert "phishing-detection-engine:3.8.0-integrated" in compose  # build-from-source tag
    assert "agentic-phishing-review:1.10.0-integrated" in compose
    assert "${AGENT_REVIEW_CONTEXT:-../../agentic-phishing-review}" in compose
    # The contract declares a reviewer-to-rag call. If the integrated stack
    # cannot reach a reference service, that declaration describes nothing: the
    # reviewer reads RAG_BASE_URL and supplies no references when it is empty.
    assert "RAG_BASE_URL" in compose
    references = (ROOT / "deploy" / "compose.references.yaml").read_text(encoding="utf-8")
    # The pin is a Compose default rather than a literal, so the overlay follows
    # whichever image was loaded. The recorded version must still be that default.
    assert (
        "phishing-rag-service:${RAG_VERSION:-"
        f"{contract['components']['rag']['version']}"
        "}"
    ) in references
    # No build section: a tag that is not loaded must fail, not silently build a
    # ~9 GB image from source.
    assert "build:" not in references
    # The overlay must stay an overlay. Compose interpolates every service it
    # parses, so moving this into the base file with a required index path would
    # break a plain `docker compose up` for deployments that do not run it.
    assert "\n  rag:\n" not in compose


def test_recorded_extension_version_matches_the_extension_repository():
    """Catch cross-repo drift where both sides of this file agree and are wrong.

    The extension version was once recorded here as one number while the
    shipped manifest said another. Nothing noticed, because the assertion above
    and the contract were the same stale constant restating each other. The manifest is the
    authority; this compares against it whenever the extension is checked out
    beside this repository, and skips when it is not.
    """
    manifest_path = ROOT.parent / "phishingshield-persian" / "manifest.json"
    if not manifest_path.is_file():
        pytest.skip("extension repository not checked out beside this one")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    contract = json.loads((ROOT / "deploy" / "COMPATIBILITY.json").read_text(encoding="utf-8"))
    recorded = contract["components"]["extension"]["version"]
    assert manifest["version"] == recorded, (
        f"extension manifest is {manifest['version']} but deploy/COMPATIBILITY.json "
        f"records {recorded}"
    )


def test_clean_docker_build_does_not_require_runtime_database():
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY var" not in dockerfile
    assert 'ARG APP_VERSION=3.8.0' in dockerfile


def test_shipped_requirements_carry_the_observability_extra():
    """The image must be able to emit the metrics the code records.

    observability is an optional extra so the library degrades to no-ops when
    it is absent. That is right for a library and was wrong for the shipped
    image: the detector image was built without these packages, so /metrics
    answered "# prometheus_client is not installed" and every recorded metric
    was a silent no-op in production.

    requirements.txt is what the Dockerfile installs (via requirements-browser
    .txt), so the extra's contents must appear there too. This keeps the two
    lists from drifting apart again.
    """
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    extra = re.search(r"observability = \[(.*?)\]", pyproject, flags=re.DOTALL)
    assert extra, "pyproject.toml no longer declares an observability extra"
    declared = set(re.findall(r'"([^"]+)"', extra.group(1)))
    assert declared, "the observability extra is empty"

    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8")
    shipped = {
        line.strip()
        for line in requirements.splitlines()
        if line.strip() and not line.strip().startswith("#")
    }
    missing = declared - shipped
    assert not missing, (
        f"declared in the observability extra but not shipped in the image: {sorted(missing)}"
    )


def test_installer_versions_match_the_stack_contract():
    """The one-command installer downloads by version, so it must not drift.

    deploy/install.sh names the release tags it fetches. If those fall behind
    COMPATIBILITY.json, the installer quietly pulls an older stack than the one
    this repository claims to ship, and nothing else would notice.
    """
    installer = (ROOT / "deploy" / "install.sh").read_text(encoding="utf-8")
    contract = json.loads((ROOT / "deploy" / "COMPATIBILITY.json").read_text(encoding="utf-8"))

    expected = {
        "DETECTOR_VERSION": contract["components"]["detector"]["version"],
        "REVIEW_VERSION": contract["components"]["reviewer"]["version"],
        "RAG_VERSION": contract["components"]["rag"]["version"],
        "STACK_VERSION": contract["stack_version"],
    }
    for name, version in expected.items():
        found = re.search(rf'^{name}="\$\{{{name}:-([^}}]+)\}}"', installer, flags=re.MULTILINE)
        assert found, f"install.sh no longer defines a default for {name}"
        assert found.group(1) == version, (
            f"install.sh defaults {name} to {found.group(1)}, "
            f"but the contract records {version}"
        )
