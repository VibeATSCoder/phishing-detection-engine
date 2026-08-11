import pytest

import persianphish_detector.domain_facts as domain_facts


@pytest.mark.asyncio
async def test_tls_probe_is_skipped_when_public_resolution_fails(monkeypatch):
    def reject_resolution(url, allow_private=False):
        raise ValueError("private_address")

    def forbidden_tls_probe(host, address, timeout_s=3.0):
        raise AssertionError("TLS probe must not run without a validated public IP")

    monkeypatch.setattr(domain_facts, "resolve_public_addresses", reject_resolution)
    monkeypatch.setattr(domain_facts, "_tls_days_remaining", forbidden_tls_probe)
    facts = await domain_facts.collect_domain_facts("https://127.0.0.1/")
    assert facts.dns_address_count is None
    assert facts.tls_days_remaining is None
    assert facts.missing
