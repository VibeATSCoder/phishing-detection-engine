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
        attempts: int = 3,
    ) -> None:
        self.timeout_s = timeout_s
        self.attempts = max(1, attempts)
        self.max_bytes = max_bytes
        self.max_redirects = max_redirects
        self.allow_private_network = allow_private_network
        self.min_quality_score = min_quality_score
        self.user_agent = user_agent

    #: Failures worth trying again. A timeout or a dropped connection says
    #: something about the moment, not about the page; an HTTP error, a refused
    #: redirect or an unsafe address says something about the page and repeating
    #: it only costs time.
    _RETRYABLE = (CrawlStatus.TIMEOUT, CrawlStatus.UNREACHABLE)

    async def fetch(self, url: str) -> CrawlEvidence:
        """Fetch, retrying the failures that are about the network.

        There was no retry at all: one httpx call, and any timeout or reset
        became crawl_failed immediately. On a slow or filtered link that is the
        common case rather than the exception, and it denied the agent the page
        entirely — the detector cannot review content it threw away.
        """
        evidence = await self._fetch_once(url)
        for attempt in range(2, self.attempts + 1):
            if evidence.status not in self._RETRYABLE:
                return evidence
            # Short, widening pause: a link that is briefly saturated clears in
            # a second or two, and waiting longer than the request itself would
            # cost more than it recovers.
            await asyncio.sleep(0.5 * (attempt - 1))
            retried = await self._fetch_once(url)
            # Keep the better outcome. A retry that fails differently should not
            # replace a first attempt that at least brought back a body.
            if retried.usable or retried.quality_score > evidence.quality_score:
                evidence = retried
            if evidence.usable:
                break
        return evidence

    async def _fetch_once(self, url: str) -> CrawlEvidence:
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
            # Split rather than one number for everything. A connection that is
            # slow to establish and a page that is slow to stream are different
            # problems, and a single budget covering both means a large page on
            # a slow link fails on time the handshake already spent. The read
            # budget is per-chunk, so a page that keeps arriving keeps its
            # deadline refreshed.
            timeout = httpx.Timeout(
                connect=min(self.timeout_s, 10.0),
                read=self.timeout_s,
                write=self.timeout_s,
                pool=self.timeout_s,
            )
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
                        interrupted = ""
                        try:
                            async for chunk in response.aiter_bytes():
                                remaining = self.max_bytes - len(body)
                                if remaining <= 0:
                                    truncated = True
                                    break
                                body.extend(chunk[:remaining])
                                if len(chunk) > remaining:
                                    truncated = True
                                    break
                        except (httpx.TimeoutException, httpx.HTTPError) as exc:
                            # The connection dropped part-way through the body.
                            # What already arrived is still the page, and on a
                            # poor link it is usually most of it — discarding it
                            # turned a slow download into crawl_failed, which
                            # then denied the agent any content at all. The
                            # quality gate below decides whether it is enough.
                            if not body:
                                raise
                            interrupted = f"{type(exc).__name__}: {exc}"
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
                        if interrupted:
                            reasons.append("body_incomplete_connection_interrupted")
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
                            error=interrupted,
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
