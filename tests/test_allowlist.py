"""Hosts cleared without inspecting the page.

An allowlist is the bluntest instrument in this service and the easiest to get
dangerously wrong. The cases that matter most here are the ones asserting a
lookalike does *not* match: clearing "google.com.verify-login.ir" would clear
exactly the attack this product exists to catch.
"""

from __future__ import annotations

import pytest

from persianphish_detector.allowlist import (
    ALLOWLISTED_DOMAINS,
    ALLOWLISTED_SUFFIXES,
    CATALOG_VERSION,
    allowlisted_domain,
)


# ------------------------------------------------------- must never match ---

@pytest.mark.parametrize(
    "url",
    [
        # The entry as a prefix of somebody else's domain. Substring matching
        # would clear every one of these.
        "https://google.com.verify-login.ir/",
        "https://filimo.com.signin.example/",
        "https://digikala.com-account.ir/",
        # The entry as a suffix of a longer label.
        "https://notgoogle.com/",
        "https://myfilimo.com/",
        "https://xgmail.com/",
        # The entry somewhere in the path or query rather than the host.
        "https://evil.ir/?next=https://google.com",
        "https://evil.ir/google.com/login",
        # Punycode anywhere in the host: this is how a homograph is spelled.
        "https://xn--80ak6aa92e.google.com/",
        "https://xn--goole-8va.com/",
        # A bare address and an empty input.
        "https://93.184.216.34/",
        "",
    ],
)
def test_a_lookalike_is_never_cleared(url: str) -> None:
    assert allowlisted_domain(url) is None, url


# ------------------------------------------------------------ must match ---

@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://www.google.com/", "google.com"),
        ("https://mail.google.com/mail/u/0/", "google.com"),
        ("https://gmail.com", "gmail.com"),
        ("https://www.yahoo.com/", "yahoo.com"),
        ("https://www.filimo.com/signin", "filimo.com"),
        ("https://www.digikala.com/", "digikala.com"),
        ("https://stackoverflow.com/questions/1", "stackoverflow.com"),
        ("https://en.wikipedia.org/wiki/Iran", "wikipedia.org"),
        ("http://aparat.com", "aparat.com"),
    ],
)
def test_the_real_site_and_its_subdomains_are_cleared(url: str, expected: str) -> None:
    assert allowlisted_domain(url) == expected


# --------------------------------------------------- the catalog itself ---

def test_every_entry_is_a_bare_registrable_domain() -> None:
    """A path, a scheme or a wildcard in an entry would never match anything,
    and a leading dot would silently widen it."""
    for entry in ALLOWLISTED_DOMAINS:
        assert entry == entry.lower().strip(), f"{entry!r} is not normalised"
        assert "/" not in entry and ":" not in entry, f"{entry!r} is not a bare domain"
        assert not entry.startswith(("*", ".")), f"{entry!r} is a pattern, not a domain"
        assert "." in entry, f"{entry!r} has no TLD"
        assert "xn--" not in entry, f"{entry!r} is punycode"


def test_no_entry_is_a_public_suffix_on_its_own() -> None:
    """An entry like "ir" or "co.uk" would clear an entire country."""
    dangerous = {"ir", "com", "net", "org", "co.uk", "co.ir", "ac.ir", "gov.ir"}
    assert not (ALLOWLISTED_DOMAINS & dangerous)


def test_every_entry_clears_itself() -> None:
    for entry in ALLOWLISTED_DOMAINS:
        assert allowlisted_domain(f"https://{entry}/") == entry
        assert allowlisted_domain(f"https://www.{entry}/") == entry


def test_the_catalog_version_is_recorded() -> None:
    """So a clearance can be traced to the list that produced it."""
    assert CATALOG_VERSION.startswith("allowlist-")


def test_the_brands_the_owner_named_are_present() -> None:
    for domain in ("filimo.com", "google.com", "gmail.com", "yahoo.com"):
        assert domain in ALLOWLISTED_DOMAINS


# ------------------------------------------------- a closed namespace ---

@pytest.mark.parametrize(
    "url",
    [
        "https://gov.ir/",
        "https://police.gov.ir/",
        "https://mail.tehran.gov.ir/inbox",
        "http://portal.mefa.gov.ir/",
    ],
)
def test_a_government_host_is_cleared(url: str) -> None:
    """gov.ir cannot be registered at will, so being inside it is already a
    statement about who operates the host."""
    assert allowlisted_domain(url) == "gov.ir"


@pytest.mark.parametrize(
    "url",
    [
        "https://gov.ir.verify-login.example/",   # the suffix as a prefix
        "https://notgov.ir/",                    # no label boundary
        "https://mygov.ir/",
        "https://evil.example/gov.ir/login",      # in the path
    ],
)
def test_a_lookalike_of_the_namespace_is_refused(url: str) -> None:
    assert allowlisted_domain(url) is None, url


def test_only_closed_namespaces_are_suffixes() -> None:
    """A registry anyone can buy from would disable this service wholesale.

    .ir and .com are open; clearing either would clear a third of the web.
    """
    for suffix in ALLOWLISTED_SUFFIXES:
        assert suffix.count(".") >= 1, f"{suffix!r} is a bare TLD"
        assert suffix not in {"ir", "com", "net", "org", "co.uk", "ac.ir", "co.ir"}


# ------------------------------------------------------------- banking ---

@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://bmi.ir/", "bmi.ir"),
        ("https://ib.bmi.ir/login", "bmi.ir"),          # internet banking
        ("https://bank.tejaratbank.ir/", "tejaratbank.ir"),
        ("https://www.cbi.ir/", "cbi.ir"),
        ("https://sep.ir/", "sep.ir"),
    ],
)
def test_a_bank_and_its_subdomains_are_cleared(url: str, expected: str) -> None:
    """The login lives on a subdomain and enumerating them would go stale."""
    assert allowlisted_domain(url) == expected


@pytest.mark.parametrize(
    "url",
    [
        "https://bmi.ir.secure-login.example/",
        "https://bankmellat.ir.verify.ir/",
        "https://ib-bmi.ir/",
        "https://xn--bmi-8va.ir/",
    ],
)
def test_a_bank_lookalike_is_never_cleared(url: str) -> None:
    """The highest-value target in Persian phishing, so the shape that matters."""
    assert allowlisted_domain(url) is None, url
