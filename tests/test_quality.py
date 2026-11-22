import pytest

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


@pytest.mark.parametrize("notice", [
    "<h1>لطفاً VPN خود را خاموش کنید</h1><p>برای دسترسی به وب‌سایت، لطفاً VPN خود را خاموش نمایید.</p>",
    "<h1>لطفاً وي‌پي‌ان خود را غيرفعال كنيد</h1><p>برای ورود به این سایت</p>",
    "<h1>Please turn off your VPN</h1><p>To access this website, disable your VPN.</p>",
])
def test_vpn_access_notice_is_blocked_even_on_http_200(notice):
    html = f"<html><head><title>Access restriction</title></head><body>{notice}<p>IP: 192.0.2.1</p></body></html>"
    assert assess_crawl_quality(200, "text/html", html) == (CrawlStatus.BLOCKED, 0.0, ["vpn_access_restricted"])


@pytest.mark.parametrize("extra", ["<input name='password'>", "<a href='/continue'>Continue</a>", "<p>VPN help and troubleshooting. </p>" * 21])
def test_vpn_text_in_interactive_or_substantive_content_is_not_a_block(extra):
    html = f"<main><h1>Please disable your VPN to access the site</h1>{extra}</main>"
    assert "vpn_access_restricted" not in assess_crawl_quality(200, "text/html", html)[2]
