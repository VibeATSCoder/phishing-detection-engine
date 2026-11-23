from __future__ import annotations

import pytest

from persianphish_detector.allowlist import ALLOWLISTED_DOMAINS, CATALOG_VERSION, allowlisted_domain


@pytest.mark.parametrize("url,entry", [
    ("https://www.google.com/", "google.com"),
    ("https://google.com", "google.com"),
    ("https://google.com/search?q=example", "google.com"),
    (
        "https://www.google.com/search?sca_esv=123&rlz=1C1GCEA&sxsrf=abc:123"
        "&q=%D8%AF%D8%B3%D8%AA%DA%AF%D8%A7%D9%87+SE+44mm"
        "&spell=1&sa=X&ved=123&biw=1920&bih=911&dpr=1",
        "google.com",
    ),
    ("https://accounts.google.com/", "google.com"),
    ("https://mail.google.com/mail/u/0/", "google.com"),
    ("https://www.digikala.com/", "digikala.com"),
    ("https://www.filimo.com/signin", "filimo.com"),
    ("https://www.yahoo.com/", "yahoo.com"),
    ("https://stackoverflow.com/", "stackoverflow.com"),
    ("https://gov.ir/", "gov.ir"),
    ("https://www.cbi.ir/", "cbi.ir"),
])
def test_curated_first_party_urls_are_cleared(url, entry):
    assert allowlisted_domain(url) == entry


@pytest.mark.parametrize("url", [
    "https://google.com.verify-login.ir/",
    "https://notgoogle.com/",
    "https://google.com@evil.ir/",
    "https://evil.ir/?next=https://google.com",
    "https://xn--80ak6aa92e.google.com/",
    "https://xn--goole-8va.com/",
    "https://google.com:8443/",
    "http://google.com/",
    "https://www.google.com/?continue=https://example.net/",
    "https://www.google.com/url",
    "https://www.google.com/search?q=example&btnI=1",
    "https://www.google.com/search?q=example&%62tnI=1",
    "https://www.google.com/search?q=example&continue=https://example.net/",
    "https://www.google.com/search?q=example;continue=https://example.net/",
    "https://www.google.com/search?q=example#page",
    "https://www.google.com/search?ei=123",
    "https://www.google.com/search?q=+",
    "https://www.google.com/search?q=first&q=second",
    "https://www.google.com/search?client& q=example",
    "https://www.google.com/search/other?q=example",
    "https://www.google.com:8443/search?q=example",
    "https://www.google.com.example.net/search?q=example",
    "https://www.google.com@example.net/search?q=example",
    "http://www.google.com/search?q=example",
    "https://docs.google.com/forms/",
    "https://custom.googleusercontent.com/",
    "https://www.google.com/%2f",
    "https://www.google.com/#page",
    "https://random.gov.ir/",
    "https://unknown.bmi.ir/login",
    "https://93.184.216.34/",
    "https://snapp.market/",
    "https://www.snapp.market/",
    "",
])
def test_other_urls_use_the_normal_detector(url):
    assert allowlisted_domain(url) is None


def test_catalog_uses_normalized_homepage_domains():
    assert not (ALLOWLISTED_DOMAINS & {"com", "ir", "co.uk", "gov.ir"})
    assert CATALOG_VERSION.startswith("allowlist-")
    for domain in ALLOWLISTED_DOMAINS:
        assert "." in domain
        assert allowlisted_domain(f"https://{domain}/") == domain
        assert allowlisted_domain(f"https://www.{domain}/") == domain


def test_operator_addition_applies_only_to_the_exact_homepage(tmp_path, monkeypatch):
    filepath = tmp_path / "allowlist.txt"
    filepath.write_text("# Trust example's first-party homepage\nportal.example.net\n")
    monkeypatch.setenv("PPD_ALLOWLIST_FILE", str(filepath))
    assert allowlisted_domain("https://portal.example.net/") == "portal.example.net"
    assert allowlisted_domain("https://nested.portal.example.net/") is None
    assert allowlisted_domain("https://portal.example.net/signup") is None
