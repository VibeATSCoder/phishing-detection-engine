from __future__ import annotations

import base64
from typing import Any, Mapping

from ..types import CrawlEvidence
from ..url_utils import cross_domain_redirect_count, normalize_url
from .quality import assess_crawl_quality


MAX_BROWSER_HTML_BYTES = 5_000_000
MAX_SCREENSHOT_BYTES = 2_000_000
MAX_NETWORK_HOSTS = 500
MAX_REDIRECTS = 20


def from_browser_payload(target_url: str, payload: Mapping[str, Any], min_quality_score: float = 0.55) -> CrawlEvidence:
    final_url = normalize_url(str(payload.get("final_url") or target_url))
    html = str(payload.get("dom_html") or "")
    if len(html.encode("utf-8", errors="replace")) > MAX_BROWSER_HTML_BYTES:
        raise ValueError("browser_html_too_large")
    screenshot = b""
    screenshot_b64 = payload.get("screenshot_base64")
    if screenshot_b64:
        screenshot = base64.b64decode(str(screenshot_b64), validate=True)
        if len(screenshot) > MAX_SCREENSHOT_BYTES:
            raise ValueError("browser_screenshot_too_large")
    redirects = [normalize_url(str(item)) for item in list(payload.get("redirect_chain") or [])[:MAX_REDIRECTS]]
    if not redirects:
        redirects = [normalize_url(target_url), final_url]
    network_hosts = sorted({str(item).lower() for item in list(payload.get("network_hosts") or [])[:MAX_NETWORK_HOSTS] if item})
    http_status = int(payload.get("http_status") or 200)
    content_type = str(payload.get("content_type") or "text/html")
    status, score, reasons = assess_crawl_quality(http_status, content_type, html, min_score=min_quality_score)
    if cross_domain_redirect_count(redirects) > 0:
        reasons.append("cross_domain_redirect")
    return CrawlEvidence(
        target_url=normalize_url(target_url),
        final_url=final_url,
        status=status,
        http_status=http_status,
        content_type=content_type,
        html=html,
        screenshot=screenshot,
        redirect_chain=redirects,
        network_hosts=network_hosts,
        source="browser_client",
        quality_score=score,
        quality_reasons=reasons,
    )
