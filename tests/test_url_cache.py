"""Regression tests for the URL-normalization cache.

Feature extraction resolves a domain for every href and src on a page, so these
helpers ran tens of thousands of times per document and idna.encode alone was
44% of extract_features. Caching them cut extraction from ~222ms to ~71ms on a
12,000-link document.

These tests assert the *mechanism* rather than a wall-clock number: timing
assertions are flaky on shared runners, but a call count is exact. If someone
removes the cache, the call-count tests fail immediately and loudly.
"""

from urllib.parse import urlsplit

import pytest

from persianphish_detector import url_utils
from persianphish_detector.url_utils import (
    UnsafeURL,
    canonical_url,
    hostname,
    normalize_url,
    registrable_domain,
)


@pytest.fixture(autouse=True)
def clear_caches():
    normalize_url.cache_clear()
    hostname.cache_clear()
    yield
    normalize_url.cache_clear()
    hostname.cache_clear()


def test_repeated_lookups_hit_the_cache():
    for _ in range(500):
        hostname("https://example.com/a/b?c=1")
    info = hostname.cache_info()
    assert info.misses == 1
    assert info.hits == 499


def test_cache_is_bounded():
    """An attacker-controlled page of unique URLs must not grow memory forever."""
    assert normalize_url.cache_parameters()["maxsize"] == 50_000
    assert hostname.cache_parameters()["maxsize"] == 50_000


def test_idna_is_not_re_encoded_for_a_repeated_host(monkeypatch):
    """The expensive call is idna.encode; prove it runs once per distinct URL."""
    calls = {"n": 0}
    real_encode = url_utils.idna.encode

    def counting_encode(value, **kwargs):
        calls["n"] += 1
        return real_encode(value, **kwargs)

    monkeypatch.setattr(url_utils.idna, "encode", counting_encode)
    normalize_url.cache_clear()
    for _ in range(200):
        normalize_url("https://example.com/page")
    assert calls["n"] == 1


def test_distinct_urls_are_each_normalized():
    for index in range(50):
        hostname(f"https://host{index}.example.com/")
    assert hostname.cache_info().misses == 50


def test_caching_does_not_change_results():
    """A cached call must return exactly what an uncached one would."""
    samples = [
        "https://Example.COM/A/../B?z=1&a=2",
        "http://example.com:80/",
        "https://xn--80ak6aa92e.example/",
        "https://sub.example.co.uk/path/",
        "https://example.com",
    ]
    normalize_url.cache_clear()
    cold = [normalize_url(url) for url in samples]
    warm = [normalize_url(url) for url in samples]
    assert cold == warm
    # And independently recomputed values agree with the cached ones.
    normalize_url.cache_clear()
    assert [normalize_url(url) for url in samples] == cold


def test_unsafe_urls_are_still_rejected_after_caching():
    """Exceptions must not be cached away, and must keep being raised."""
    for _ in range(3):
        with pytest.raises(UnsafeURL):
            normalize_url("ftp://example.com/")
        with pytest.raises(UnsafeURL):
            normalize_url("")
        with pytest.raises(UnsafeURL):
            normalize_url("https://user:pass@example.com/")


def test_hostname_and_registrable_domain_stay_consistent():
    assert hostname("https://a.b.example.co.uk/x") == "a.b.example.co.uk"
    assert registrable_domain("https://a.b.example.co.uk/x") == "example.co.uk"
    assert urlsplit(canonical_url("https://Example.com/a?b=1")).hostname == "example.com"


def test_extraction_resolves_each_distinct_url_once():
    """End-to-end: a page repeating two links must not re-normalize per element."""
    from persianphish_detector.crawl.evidence import from_browser_payload
    from persianphish_detector.domain_facts import DomainFacts
    from persianphish_detector.features import extract_features

    row = '<div><a href="/x">l</a><img src="/i.png"></div>'
    html = f"<html><head><title>t</title></head><body>{row * 400}</body></html>"
    evidence = from_browser_payload(
        "https://example.com/",
        {
            "final_url": "https://example.com/",
            "http_status": 200,
            "content_type": "text/html",
            "dom_html": html,
            "redirect_chain": [],
            "network_hosts": [],
        },
        0.0,
    )
    hostname.cache_clear()
    extract_features(evidence, DomainFacts(registrable_domain="example.com"))
    info = hostname.cache_info()
    # 800 elements, but only a handful of distinct absolute URLs.
    assert info.misses <= 5, f"expected few distinct URLs, saw {info.misses}"
    assert info.hits > 1000, "cache is not being exercised by extraction"
