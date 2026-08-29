from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class Verdict(str, Enum):
    LEGITIMATE = "legitimate"
    PHISHING = "phishing"
    SUSPICIOUS = "suspicious"
    CRAWL_FAILED = "crawl_failed"


class CrawlStatus(str, Enum):
    OK = "ok"
    PARTIAL = "partial"
    BLOCKED = "blocked"
    HTTP_ERROR = "http_error"
    TIMEOUT = "timeout"
    NON_HTML = "non_html"
    UNREACHABLE = "unreachable"
    INVALID_URL = "invalid_url"


@dataclass
class CrawlEvidence:
    target_url: str
    final_url: str = ""
    status: CrawlStatus = CrawlStatus.UNREACHABLE
    http_status: Optional[int] = None
    content_type: str = ""
    html: str = ""
    screenshot: bytes = b""
    redirect_chain: List[str] = field(default_factory=list)
    response_headers: Dict[str, str] = field(default_factory=dict)
    network_hosts: List[str] = field(default_factory=list)
    source: str = "http"
    quality_score: float = 0.0
    quality_reasons: List[str] = field(default_factory=list)
    elapsed_ms: float = 0.0
    error: str = ""

    @property
    def usable(self) -> bool:
        return self.status == CrawlStatus.OK and bool(self.html)

    def public_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload.pop("html", None)
        payload.pop("screenshot", None)
        payload["status"] = self.status.value
        payload["html_bytes"] = len(self.html.encode("utf-8", errors="replace"))
        payload["screenshot_bytes"] = len(self.screenshot)
        return payload


@dataclass
class DomainFacts:
    registrable_domain: str = ""
    domain_age_days: Optional[float] = None
    dns_address_count: Optional[int] = None
    tls_days_remaining: Optional[float] = None
    popularity_rank: Optional[int] = None
    missing: bool = True


@dataclass
class DetectionResult:
    request_id: str
    url: str
    final_url: str
    verdict: Verdict
    risk_score: float
    stage: str
    crawl_status: CrawlStatus
    reason_codes: List[str] = field(default_factory=list)
    model_scores: Dict[str, Optional[float]] = field(default_factory=dict)
    model_version: str = "v3"
    latency_ms: Dict[str, float] = field(default_factory=dict)
    evidence: List[Dict[str, str]] = field(default_factory=list)
    evidence_summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["verdict"] = self.verdict.value
        payload["crawl_status"] = self.crawl_status.value
        return payload
