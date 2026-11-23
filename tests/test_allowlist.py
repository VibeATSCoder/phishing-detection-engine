from __future__ import annotations

import pytest

from persianphish_detector.allowlist import ALLOWLISTED_DOMAINS, CATALOG_VERSION, allowlisted_domain


@pytest.mark.parametrize("url,entry", [
    ("https://www.google.com/", "google.com"),
    ("https://google.com", "google.com"),
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
