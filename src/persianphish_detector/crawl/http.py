from __future__ import annotations

import asyncio
import re
import time
from typing import Dict, Optional

from ..types import CrawlEvidence, CrawlStatus
from ..url_utils import UnsafeURL, normalize_url, resolve_public_addresses, safe_redirect_url
from .quality import assess_crawl_quality


DEFAULT_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)


def decode_body(data: bytes, content_type: str) -> str:
    declared = None
    match = re.search(r"charset\s*=\s*['\"]?([^;,'\"\s]+)", content_type or "", re.I)
    if match:
        declared = match.group(1)
    candidates = [declared, "utf-8-sig", "utf-8", "windows-1256", "cp1256", "latin-1"]
    best = ""
    best_score = None
    for encoding in dict.fromkeys(item for item in candidates if item):
        try:
            text = data.decode(encoding, errors="replace")
        except (LookupError, UnicodeError):
            continue
        score = (text.count("\ufffd"), sum(text.count(marker) for marker in ("\u00d8", "\u00d9", "\u00db", "\u00c3")))
        if best_score is None or score < best_score:
            best, best_score = text, score
        if score == (0, 0):
            break
    return best


class HttpCrawler:
    def __init__(
        self,
        *,
        timeout_s: float = 8.0,
        max_bytes: int = 10_000_000,
        max_redirects: int = 5,
        allow_private_network: bool = False,
        min_quality_score: float = 0.55,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self.timeout_s = timeout_s
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.allow_private_network = allow_private_network
        self.min_quality_score = min_quality_score
        self.user_agent = user_agent

    async def fetch(self, url: str) -> CrawlEvidence:
        started = time.perf_counter()
        try:
            target = normalize_url(url)
            await asyncio.to_thread(resolve_public_addresses, target, self.allow_private_network)
        except UnsafeURL as exc:
            return CrawlEvidence(
                target_url=url,
                status=CrawlStatus.INVALID_URL,
                quality_reasons=[str(exc)],
                error=str(exc),
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            return CrawlEvidence(
                target_url=target,
                status=CrawlStatus.UNREACHABLE,
                quality_reasons=["httpx_not_installed"],
                error=str(exc),
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )

        current = target
        redirects = [target]
        headers = {
            "user-agent": self.user_agent,
            "accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "accept-language": "fa-IR,fa;q=0.9,en-US;q=0.7,en;q=0.6",
            "cache-control": "no-cache",
        }
        try:
            timeout = httpx.Timeout(self.timeout_s)
            async with httpx.AsyncClient(
                timeout=timeout,
                follow_redirects=False,
                verify=True,
                headers=headers,
                trust_env=False,
            ) as client:
                for _ in range(self.max_redirects + 1):
                    async with client.stream("GET", current) as response:
                        if response.status_code in {301, 302, 303, 307, 308} and response.headers.get("location"):
                            if len(redirects) > self.max_redirects:
                                return CrawlEvidence(
                                    target_url=target,
                                    final_url=current,
                                    status=CrawlStatus.HTTP_ERROR,
                                    http_status=response.status_code,
                                    redirect_chain=redirects,
                                    quality_reasons=["too_many_redirects"],
                                    elapsed_ms=(time.perf_counter() - started) * 1000,
                                )
                            current = safe_redirect_url(current, response.headers["location"])
                            await asyncio.to_thread(resolve_public_addresses, current, self.allow_private_network)
                            redirects.append(current)
                            continue
                        body = bytearray()
                        truncated = False
                        async for chunk in response.aiter_bytes():
                            remaining = self.max_bytes - len(body)
                            if remaining <= 0:
                                truncated = True
                                break
                            body.extend(chunk[:remaining])
                            if len(chunk) > remaining:
                                truncated = True
                                break
                        data = bytes(body)
                        content_type = response.headers.get("content-type", "")
                        html = decode_body(data, content_type)
                        status, score, reasons = assess_crawl_quality(
                            response.status_code,
                            content_type,
                            html,
                            min_score=self.min_quality_score,
                        )
                        if truncated:
                            reasons.append("html_truncated_at_byte_limit")
                        selected_headers: Dict[str, str] = {
                            key.lower(): value
                            for key, value in response.headers.items()
                            if key.lower() in {
                                "content-type", "content-length", "server", "location",
                                "content-security-policy", "strict-transport-security", "x-frame-options",
                            }
                        }
                        return CrawlEvidence(
                            target_url=target,
                            final_url=str(response.url),
                            status=status,
                            http_status=response.status_code,
                            content_type=content_type,
                            html=html,
                            redirect_chain=redirects,
                            response_headers=selected_headers,
                            source="http",
                            quality_score=score,
                            quality_reasons=reasons,
                            elapsed_ms=(time.perf_counter() - started) * 1000,
                        )
        except httpx.TimeoutException as exc:
            status = CrawlStatus.TIMEOUT
            error = f"{type(exc).__name__}: {exc}"
        except (httpx.HTTPError, UnsafeURL) as exc:
            status = CrawlStatus.UNREACHABLE if not isinstance(exc, UnsafeURL) else CrawlStatus.INVALID_URL
            error = f"{type(exc).__name__}: {exc}"
        return CrawlEvidence(
            target_url=target,
            final_url=current,
            status=status,
            redirect_chain=redirects,
            quality_reasons=[status.value],
            error=error,
            elapsed_ms=(time.perf_counter() - started) * 1000,
        )
