import pytest

from persianphish_detector.url_utils import (
    UnsafeURL,
    canonical_url,
    registrable_domain,
    resolve_public_addresses,
    tcn_domain_input,
)


def test_canonical_url_sorts_query_and_removes_fragment():
    assert canonical_url("soft98.ir/path?z=2&a=1#part") == "https://soft98.ir/path?a=1&z=2"


def test_registrable_domain_under_ir_public_suffix():
    assert registrable_domain("https://portal.example.ac.ir/login") == "example.ac.ir"
    assert registrable_domain("https://cdn.soft98.ir/") == "soft98.ir"


def test_tcn_domain_input_removes_scheme_port_path_query_and_fragment():
    assert tcn_domain_input("HTTPS://WWW.Google.COM:8443/a/b/c?q=long-value#fragment") == "www.google.com"


def test_userinfo_is_rejected():
    with pytest.raises(UnsafeURL, match="userinfo_not_allowed"):
        canonical_url("https://trusted.example@evil.example/login")


def test_invalid_port_is_reported_as_unsafe_url():
    with pytest.raises(UnsafeURL, match="invalid_url_authority"):
        canonical_url("https://example.com:not-a-port/")


def test_loopback_is_rejected_by_ssrf_guard():
    with pytest.raises(UnsafeURL, match="private_or_reserved_address"):
        resolve_public_addresses("http://127.0.0.1/")
