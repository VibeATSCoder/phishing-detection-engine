from __future__ import annotations

import asyncio
import time
from typing import Any, Dict, List, Set
from urllib.parse import urlsplit

from ..types import CrawlEvidence, CrawlStatus
from ..url_utils import UnsafeURL, normalize_url, resolve_public_addresses
from .http import DEFAULT_USER_AGENT
from .quality import assess_crawl_quality


class BrowserCrawler:
    """Small pooled Playwright crawler used only after the HTTP quality gate."""

    def __init__(
        self,
        *,
        timeout_s: float = 12.0,
        allow_private_network: bool = False,
        min_quality_score: float = 0.55,
        concurrency: int = 2,
    ) -> None:
        self.timeout_s = timeout_s
        self.allow_private_network = allow_private_network
        self.min_quality_score = min_quality_score
        self._semaphore = asyncio.Semaphore(concurrency)
        self._playwright: Any = None
        self._browser: Any = None
        self._start_lock = asyncio.Lock()

    async def start(self) -> None:
        async with self._start_lock:
            if self._browser is not None:
                return
            from playwright.async_api import async_playwright

            self._playwright = await async_playwright().start()
            self._browser = await self._playwright.chromium.launch(
                headless=True,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-extensions"],
            )

    async def close(self) -> None:
        if self._browser is not None:
            await self._browser.close()
            self._browser = None
        if self._playwright is not None:
            await self._playwright.stop()
            self._playwright = None

    async def fetch(self, url: str) -> CrawlEvidence:
        started = time.perf_counter()
        try:
            target = normalize_url(url)
            await asyncio.to_thread(resolve_public_addresses, target, self.allow_private_network)
            await self.start()
        except (UnsafeURL, ImportError, RuntimeError) as exc:
            return CrawlEvidence(
                target_url=url,
                status=CrawlStatus.INVALID_URL if isinstance(exc, UnsafeURL) else CrawlStatus.UNREACHABLE,
                source="browser",
                quality_reasons=["browser_unavailable"],
                error=f"{type(exc).__name__}: {exc}",
                elapsed_ms=(time.perf_counter() - started) * 1000,
            )

        async with self._semaphore:
            context = await self._browser.new_context(
                viewport={"width": 1365, "height": 900},
                locale="fa-IR",
                timezone_id="Asia/Tehran",
                ignore_https_errors=False,
                user_agent=DEFAULT_USER_AGENT,
                accept_downloads=False,
            )
            page = await context.new_page()
            network_hosts: Set[str] = set()
            redirects: List[str] = [target]
            response_headers: Dict[str, str] = {}
            validated_hosts: Set[str] = {urlsplit(target).hostname or ""}

            async def validate_request(route: Any) -> None:
                request_url = route.request.url
                if not request_url.startswith(("http://", "https://")):
                    await route.continue_()
                    return
                request_host = (urlsplit(request_url).hostname or "").lower()
                try:
                    if request_host not in validated_hosts:
                        await asyncio.to_thread(resolve_public_addresses, request_url, self.allow_private_network)
                        validated_hosts.add(request_host)
                except UnsafeURL:
                    await route.abort("blockedbyclient")
                    return
                await route.continue_()

            def capture_request(request: Any) -> None:
                host = (urlsplit(request.url).hostname or "").lower()
                if host:
                    network_hosts.add(host)

            page.on("request", capture_request)
            await page.route("**/*", validate_request)
            try:
                response = await page.goto(
                    target,
                    wait_until="domcontentloaded",
                    timeout=int(self.timeout_s * 1000),
                )
                await page.wait_for_timeout(1000)
                final_url = page.url or target
                if final_url != redirects[-1]:
                    redirects.append(final_url)
                status_code = response.status if response else None
                if response:
                    all_headers = await response.all_headers()
                    response_headers = {
                        key: value for key, value in all_headers.items()
                        if key in {"content-type", "server", "content-security-policy", "strict-transport-security", "x-frame-options"}
                    }
                content_type = response_headers.get("content-type", "text/html")
                html = await page.content()
                screenshot = await page.screenshot(type="jpeg", quality=70, full_page=False)
                crawl_status, score, reasons = assess_crawl_quality(
                    status_code,
                    content_type,
                    html,
                    min_score=self.min_quality_score,
                )
                return CrawlEvidence(
                    target_url=target,
                    final_url=final_url,
                    status=crawl_status,
                    http_status=status_code,
                    content_type=content_type,
                    html=html,
                    screenshot=screenshot,
                    redirect_chain=redirects,
                    response_headers=response_headers,
                    network_hosts=sorted(network_hosts),
                    source="browser",
                    quality_score=score,
                    quality_reasons=reasons,
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                )
            except Exception as exc:
                name = type(exc).__name__.lower()
                status = CrawlStatus.TIMEOUT if "timeout" in name else CrawlStatus.UNREACHABLE
                return CrawlEvidence(
                    target_url=target,
                    final_url=page.url or target,
                    status=status,
                    source="browser",
                    network_hosts=sorted(network_hosts),
                    quality_reasons=[status.value],
                    error=f"{type(exc).__name__}: {exc}",
                    elapsed_ms=(time.perf_counter() - started) * 1000,
                )
            finally:
                await context.close()
