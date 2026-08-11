from persianphish_detector.crawl.quality import assess_crawl_quality
from persianphish_detector.types import CrawlStatus


SOFT98_LITESPEED_403 = """<!doctype html><html><head><title>403 Forbidden</title></head>
<body><h1>403</h1><h2>Forbidden</h2><p>Access to this resource on the server is denied!</p>
<p>Proudly powered by LiteSpeed Web Server</p></body></html>"""


def test_http_403_is_blocked_even_with_html_body():
    status, score, reasons = assess_crawl_quality(403, "text/html", SOFT98_LITESPEED_403)
    assert status == CrawlStatus.BLOCKED
    assert score == 0.0
    assert "http_403" in reasons


def test_litespeed_error_page_is_blocked_when_proxy_hides_status():
    status, score, reasons = assess_crawl_quality(200, "text/html", SOFT98_LITESPEED_403)
    assert status == CrawlStatus.BLOCKED
    assert "challenge_or_error_page" in reasons


def test_normal_page_is_usable():
    links = "".join(f'<a href="/item/{index}">item {index}</a>' for index in range(30))
    html = f"<html><head><title>Soft98 software downloads</title></head><body><main><article>{links}</article></main></body></html>"
    status, score, reasons = assess_crawl_quality(200, "text/html; charset=utf-8", html)
    assert status == CrawlStatus.OK
    assert score >= 0.55
