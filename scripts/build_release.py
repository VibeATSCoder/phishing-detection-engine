from __future__ import annotations

import argparse
import hashlib
import json
import platform
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path


ROOT_FILES = {
    ".env.example", ".dockerignore", ".gitattributes", ".gitignore", "AGENTS.md", "Dockerfile", "README.md", "pyproject.toml",
    "requirements.txt", "requirements-browser.txt", "requirements-notebook.txt", "requirements-tcn.txt",
}
DIRECTORIES = {"src", "tests", "scripts", "docs", "notebooks", "deploy"}
DATA_FILES = {
    "data/processed/realworld_v3_features.csv",
    "data/processed/realworld_v3_features_summary.json",
    "data/processed/realworld_v3_quality_issues.csv",
}
ARTIFACT_FILES = {
    "artifacts/v3/detector_v3.joblib",
    "artifacts/v3/detector_v3_metrics.json",
    "artifacts/v3/detector_v3_feature_importance.csv",
    "artifacts/v3/detector_v3_test_predictions.csv",
    "artifacts/v3/detector_v3_weak_stress_predictions.csv",
    "artifacts/v3/detector_v3_tcn.joblib",
    "artifacts/v3/url_tcn.onnx",
    "artifacts/v3/url_tcn.pt",
    "artifacts/v3/url_tcn_metrics.json",
    "artifacts/v3/url_tcn_test_predictions.csv",
    "artifacts/v3/release_validation.json",
}
def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def selected_files(root: Path) -> list[Path]:
    result: set[Path] = set()
    for name in ROOT_FILES | DATA_FILES | ARTIFACT_FILES:
        path = root / name
        if path.is_file():
            result.add(path)
    for directory in DIRECTORIES:
        base = root / directory
        if not base.exists():
            continue
        for path in base.rglob("*"):
            if not path.is_file():
                continue
            if "__pycache__" in path.parts or path.suffix in {".pyc", ".pyo"}:
                continue
            result.add(path)
    return sorted(result, key=lambda path: path.relative_to(root).as_posix())


def build(root: Path, destination: Path) -> dict[str, object]:
    files = selected_files(root)
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8")
    version_match = re.search(r'^version\s*=\s*"([^"]+)"', pyproject, flags=re.MULTILINE)
    if not version_match:
        raise ValueError("project_version_not_found")
    version = version_match.group(1)
    manifest = {
        "release": f"phishing-detection-engine-v{version}",
        "version": version,
        "created_at_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "file_count": len(files),
        "files": [
            {
                "path": path.relative_to(root).as_posix(),
                "bytes": path.stat().st_size,
                "sha256": sha256(path),
            }
            for path in files
        ],
    }
    manifest_path = root / "release_manifest.json"
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    destination.parent.mkdir(parents=True, exist_ok=True)
    package_root = f"phishing-detection-engine-v{version}"
    with zipfile.ZipFile(destination, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for path in files:
            archive.write(path, f"{package_root}/{path.relative_to(root).as_posix()}")
        archive.write(manifest_path, f"{package_root}/release_manifest.json")
    manifest["archive"] = {
        "path": str(destination),
        "bytes": destination.stat().st_size,
        "sha256": sha256(destination),
    }
    print(json.dumps(manifest["archive"], indent=2))
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--output", default="release/phishing-detection-engine-v3.2.1.zip")
    args = parser.parse_args()
    build(Path(args.root).resolve(), Path(args.output).resolve())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
