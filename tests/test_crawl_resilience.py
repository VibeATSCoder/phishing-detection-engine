"""Crawling has to survive the connection it is actually given.

The HTTP crawler made one attempt with a single timeout covering connect and
read, discarded any body that arrived before a failure, and the browser fallback
was offered only for PARTIAL and BLOCKED. On a slow or filtered link — the
common case for this deployment, not the exception — a transient timeout became
crawl_failed immediately, and the agent was then denied the page entirely. The
detector cannot review content it threw away.
"""

from __future__ import annotations

import asyncio
import http.server
import threading
import time

import pytest

from persianphish_detector.crawl.http import HttpCrawler
from persianphish_detector.types import CrawlStatus


PAGE = (
    b"<html><head><title>Test Page</title></head><body>"
    + b"<p>content</p>" * 400
    + b"</body></html>"
)


class _Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    slow_hits = 0

    def log_message(self, *args):  # silence the test run
        pass

    def do_GET(self):
        if self.path == "/slow-twice":
            type(self).slow_hits += 1
            if type(self).slow_hits <= 2:
                time.sleep(10)
                return
        if self.path == "/cut":
            # Promise three times what we send, then hang up.
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(PAGE) * 3))
            self.end_headers()
            self.wfile.write(PAGE)
            self.wfile.flush()
            self.close_connection = True
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(PAGE)))
        self.end_headers()
        self.wfile.write(PAGE)


@pytest.fixture(scope="module")
def server():
    _Handler.slow_hits = 0
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def crawler(**kwargs) -> HttpCrawler:
    return HttpCrawler(timeout_s=2.0, allow_private_network=True, **kwargs)


def test_a_transient_timeout_is_retried(server: str) -> None:
    """Two timeouts then a success, which one attempt could never reach."""
    evidence = asyncio.run(crawler(attempts=3).fetch(f"{server}/slow-twice"))
    assert evidence.status is CrawlStatus.OK
    assert evidence.usable
    assert "Test Page" in evidence.html


def test_one_attempt_gives_up_where_three_recover(server: str) -> None:
    _Handler.slow_hits = 0
    evidence = asyncio.run(crawler(attempts=1).fetch(f"{server}/slow-twice"))
    assert not evidence.usable, "the old single-attempt behaviour"


def test_a_body_cut_off_mid_stream_is_kept(server: str) -> None:
    """What arrived is still the page, and on a poor link it is most of it.

    Discarding it turned a slow download into crawl_failed, which then denied
    the agent any content at all.
    """
    evidence = asyncio.run(crawler(attempts=1).fetch(f"{server}/cut"))
    assert evidence.html, "the partial body must survive"
    assert "Test Page" in evidence.html
    assert "body_incomplete_connection_interrupted" in evidence.quality_reasons


def test_a_healthy_page_is_fetched_once(server: str) -> None:
    """Retries must not cost anything when nothing is wrong."""
    started = time.perf_counter()
    evidence = asyncio.run(crawler(attempts=3).fetch(f"{server}/ok"))
    assert evidence.usable
    assert time.perf_counter() - started < 2.0, "a healthy fetch should not retry"


def test_the_connect_and_read_budgets_are_separate() -> None:
    """One number for everything means a large page fails on handshake time."""
    source = (
        __import__("pathlib").Path("src/persianphish_detector/crawl/http.py")
        .read_text(encoding="utf-8")
    )
    assert "connect=" in source and "read=" in source


def test_the_browser_is_tried_after_a_timeout_not_only_a_block() -> None:
    """Timeout and reset are the failures a poor link actually produces, and
    they went straight to crawl_failed with the browser sitting unused."""
    source = (
        __import__("pathlib").Path("src/persianphish_detector/orchestrator.py")
        .read_text(encoding="utf-8")
    )
    block = source.split("not evidence.usable\n            and self.browser", 1)[1][:400]
    assert "CrawlStatus.TIMEOUT" in block
    assert "CrawlStatus.UNREACHABLE" in block
