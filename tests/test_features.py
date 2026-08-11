from persianphish_detector.features import FEATURE_COLUMNS, extract_features
from persianphish_detector.types import CrawlEvidence, CrawlStatus, DomainFacts


def evidence(html: str, url: str = "https://soft98.ir/") -> CrawlEvidence:
    return CrawlEvidence(
        target_url=url,
        final_url=url,
        status=CrawlStatus.OK,
        http_status=200,
        content_type="text/html",
        html=html,
        redirect_chain=[url],
        quality_score=1.0,
    )


def test_feature_schema_is_complete_and_relative_links_are_internal():
    html = """<html dir="rtl"><head><title>Soft98 دانلود نرم افزار</title>
    <link rel="icon" href="/favicon.ico"></head><body>
    <a href="/windows">Windows</a><a href="https://example.net/help">Help</a>
    <form action="/login"><input type="email"><input type="password"><button>ورود</button></form>
    </body></html>"""
    row = extract_features(evidence(html), DomainFacts(registrable_domain="soft98.ir"))
    assert list(row) == FEATURE_COLUMNS
    assert row["internal_link_count_log"] > 0
    assert row["external_link_count_log"] > 0
    assert row["external_form_action_count"] == 0
    assert row["favicon_same_domain"] == 1
    assert row["persian_character_ratio"] > 0


def test_external_credential_form_is_detected():
    html = """<html><head><title>Account login</title></head><body>
    <form action="https://collector.example.net/submit"><input type="password"></form>
    </body></html>"""
    row = extract_features(evidence(html, "https://brand.example.com/"))
    assert row["external_form_action_count"] == 1
    assert row["form_action_cross_domain_ratio"] == 1
