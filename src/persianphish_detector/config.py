from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _env_bool(name: str, default: bool) -> bool:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _env_float(name: str, default: float, *, minimum: float, maximum: float) -> float:
    value = float(os.getenv(name, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"{name}_out_of_range")
    return value


def _env_int(name: str, default: int, *, minimum: int, maximum: int) -> int:
    value = int(os.getenv(name, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"{name}_out_of_range")
    return value


@dataclass(frozen=True)
class DetectorConfig:
    artifact_path: Path
    intel_db_path: Path
    review_db_path: Path
    result_dir: Path
    agent_base_url: str = ""
    agent_api_key: str = ""
    agent_timeout_s: float = 60.0
    agent_poll_interval_s: float = 0.25
    api_key: str = ""
    use_browser: bool = True
    allow_private_network: bool = False
    http_timeout_s: float = 8.0
    http_attempts: int = 3
    browser_timeout_s: float = 12.0
    max_html_bytes: int = 10_000_000
    max_redirects: int = 5
    min_quality_score: float = 0.55
    # eNamad verification is a live call to a third-party registry, so it is
    # opt-in. Absent or unreachable, it produces no signal in either direction.
    # The forest was trained on bare origins only: not one of the 935
    # legitimate rows carries a URL path. Scoring a browsed subpage is therefore
    # out of distribution, so the origin is scored instead. See
    # _rf_input_features in orchestrator.py.
    score_origin: bool = True
    # Registry evidence with an authority behind it, and the strongest
    # legitimacy signal available for an Iranian site. Only ever acts when the
    # page actually shows a badge: absence means nothing and is never counted
    # against a site. Confirmed to extract on browser-rendered pages —
    # digikala.com, alibaba.ir, tapsi.ir, sheypoor.com and zarinpal.com all
    # expose a seal in the rendered DOM though not in server HTML — and the
    # check already runs after the browser pass, so it sees that DOM.
    #
    # On a network with no route to the registry every attempt returns
    # unavailable, which is not an answer, so a breaker stops asking after three
    # consecutive failures. That bounds the cost of enabling this to three
    # timeouts per cooldown rather than one per review.
    enamad_verify: bool = True
    enamad_timeout_s: float = 8.0

    @classmethod
    def from_env(cls, root: Path | None = None) -> "DetectorConfig":
        base = (root or Path.cwd()).resolve()
        return cls(
            artifact_path=Path(os.getenv("PPD_MODEL_PATH", base / "artifacts" / "v3" / "detector_v3_tcn.joblib")),
            intel_db_path=Path(os.getenv("PPD_INTEL_DB", base / "var" / "intel.sqlite3")),
            review_db_path=Path(os.getenv("PPD_REVIEW_DB", base / "var" / "review.sqlite3")),
            result_dir=Path(os.getenv("PPD_RESULT_DIR", base / "var" / "results")),
            agent_base_url=os.getenv("PPD_AGENT_BASE_URL", "").rstrip("/"),
            agent_api_key=os.getenv("PPD_AGENT_API_KEY", ""),
            agent_timeout_s=_env_float("PPD_AGENT_TIMEOUT_S", 60.0, minimum=2.0, maximum=300.0),
            agent_poll_interval_s=_env_float(
                "PPD_AGENT_POLL_INTERVAL_S", 0.25, minimum=0.05, maximum=5.0
            ),
            api_key=os.getenv("PPD_API_KEY", ""),
            use_browser=_env_bool("PPD_USE_BROWSER", True),
            allow_private_network=_env_bool("PPD_ALLOW_PRIVATE_NETWORK", False),
            http_timeout_s=_env_float("PPD_HTTP_TIMEOUT_S", 8.0, minimum=1.0, maximum=60.0),
            http_attempts=_env_int("PPD_HTTP_ATTEMPTS", 3, minimum=1, maximum=6),
            browser_timeout_s=_env_float("PPD_BROWSER_TIMEOUT_S", 12.0, minimum=2.0, maximum=120.0),
            max_html_bytes=_env_int(
                "PPD_MAX_HTML_BYTES", 10_000_000, minimum=100_000, maximum=20_000_000
            ),
            max_redirects=_env_int("PPD_MAX_REDIRECTS", 5, minimum=0, maximum=10),
            min_quality_score=_env_float(
                "PPD_MIN_QUALITY_SCORE", 0.55, minimum=0.0, maximum=1.0
            ),
            score_origin=_env_bool("PPD_SCORE_ORIGIN", True),
            enamad_verify=_env_bool("PPD_ENAMAD_VERIFY", True),
            enamad_timeout_s=_env_float("PPD_ENAMAD_TIMEOUT_S", 8.0, minimum=1.0, maximum=30.0),
        )
