from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit


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
    agent_prefetch_references: bool = False
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
    fast_models_enabled: bool = True
    # With an endpoint and model configured, callers can opt in per request.
    jev_enabled: bool = False
    jev_base_url: str = ""
    jev_model: str = ""
    jev_api_format: str = "chat_completions"
    jev_api_key: str = ""
    jev_timeout_s: float = 20.0
    jev_max_text_chars: int = 8000
    jev_escalate_threshold: float = 0.20
    jev_min_clear_confidence: float = 0.80
    # Legacy use_jev/use_rf callers keep their opt-in standalone behavior.
    jev_short_circuit_legit: bool = False
    jev_pipeline_early_clear: bool = True
    jev_legit_threshold: float = 0.05
    jev_local_model_path: Path | None = None
    jev_local_auto_flag: bool = False
    trusted_urls_enabled: bool = True
    trusted_url_ttl_s: int = 3600
    trusted_rag_url_ttl_s: int = 86400
    trusted_url_min_confidence: float = 0.90
    trusted_url_max_risk: float = 0.03

    def __post_init__(self) -> None:
        if self.jev_api_format not in {"chat_completions", "decisions"}:
            raise ValueError("invalid_jev_api_format")
        if bool(self.jev_base_url) != bool(self.jev_model.strip()):
            raise ValueError("jev_requires_base_url_and_model")
        if self.jev_enabled and not (self.jev_base_url or self.jev_local_model_path):
            raise ValueError("jev_requires_provider_or_local_model")
        if self.jev_local_auto_flag and not self.jev_local_model_path:
            raise ValueError("jev_local_auto_flag_requires_model")
        if self.jev_base_url:
            endpoint = urlsplit(self.jev_base_url)
            if (
                endpoint.scheme not in {"http", "https"} or not endpoint.hostname
                or endpoint.username is not None or endpoint.query or endpoint.fragment
            ):
                raise ValueError("invalid_jev_base_url")
        if self.jev_short_circuit_legit and not self.jev_base_url:
            raise ValueError("jev_clear_requires_base_url_and_model")

    @classmethod
    def from_env(cls, root: Path | None = None) -> "DetectorConfig":
        base = (root or Path.cwd()).resolve()
        local_jev_path = os.getenv("PPD_JEV_LOCAL_MODEL_PATH", "").strip()
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
            agent_prefetch_references=_env_bool("PPD_AGENT_PREFETCH_REFERENCES", False),
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
            fast_models_enabled=_env_bool("PPD_FAST_MODELS_ENABLED", True),
            jev_enabled=_env_bool("PPD_JEV_ENABLED", False),
            jev_base_url=os.getenv("PPD_JEV_BASE_URL", "").rstrip("/"),
            jev_model=os.getenv("PPD_JEV_MODEL", "").strip(),
            jev_api_format=os.getenv("PPD_JEV_API_FORMAT", "chat_completions").strip().lower(),
            jev_api_key=os.getenv("PPD_JEV_API_KEY", ""),
            jev_local_model_path=Path(local_jev_path) if local_jev_path else None,
            jev_local_auto_flag=_env_bool("PPD_JEV_LOCAL_AUTO_FLAG", False),
            jev_timeout_s=_env_float("PPD_JEV_TIMEOUT_S", 20.0, minimum=1.0, maximum=120.0),
            jev_max_text_chars=_env_int(
                "PPD_JEV_MAX_TEXT_CHARS", 8000, minimum=500, maximum=40_000
            ),
            jev_escalate_threshold=_env_float(
                "PPD_JEV_ESCALATE_THRESHOLD", 0.20, minimum=0.0, maximum=1.0
            ),
            jev_min_clear_confidence=_env_float(
                "PPD_JEV_MIN_CLEAR_CONFIDENCE", 0.80, minimum=0.0, maximum=1.0
            ),
            jev_short_circuit_legit=_env_bool("PPD_JEV_SHORT_CIRCUIT_LEGIT", False),
            jev_pipeline_early_clear=_env_bool("PPD_JEV_PIPELINE_EARLY_CLEAR", True),
            jev_legit_threshold=_env_float(
                "PPD_JEV_LEGIT_THRESHOLD", 0.05, minimum=0.0, maximum=0.5
            ),
            trusted_urls_enabled=_env_bool("PPD_TRUSTED_URLS_ENABLED", True),
            trusted_url_ttl_s=_env_int("PPD_TRUSTED_URL_TTL_S", 3600, minimum=60, maximum=86400),
            trusted_rag_url_ttl_s=_env_int("PPD_TRUSTED_RAG_URL_TTL_S", 86400, minimum=60, maximum=86400),
            trusted_url_min_confidence=_env_float(
                "PPD_TRUSTED_URL_MIN_CONFIDENCE", 0.90, minimum=0.90, maximum=1.0
            ),
            trusted_url_max_risk=_env_float("PPD_TRUSTED_URL_MAX_RISK", 0.03, minimum=0.0, maximum=0.05),
        )
