"""eNamad trust-seal extraction and verification.

Fixtures mirror what the live service actually returns, measured on 2026-08-31:

    Referer zarinpal.com  ->  HTTP 200, ~82 KB, certificate names zarinpal.com
    any other Referer     ->  HTTP 500, a fixed ~10 KB error page
    no Referer            ->  HTTP 500, the same error page

That 500 is eNamad's refusal, and it is the whole reason this signal works: a
phishing page can copy a badge's markup, but it cannot make eNamad certify a
domain the code was not issued to.

The tests that matter most are the ones separating a refusal from an outage. If
those two are ever conflated, an eNamad outage becomes an accusation against
every site carrying a seal.
"""

from __future__ import annotations

import asyncio

import pytest

from persianphish_detector.enamad import (
    CONTROL_SEAL,
    clear_cache,
    EnamadSeal,
    certified_domain_from_page,
    extract_seal,
    service_is_answering,
    verify_seal,
)

# The badge as zarinpal.com actually serves it, entities and all.
REAL_BADGE = (
    '<a referrerpolicy="origin" target="_blank" '
    'href="https://trustseal.enamad.ir/?id=64418&amp;Code=4o1tQMcRX45sQDkUnGiC">'
    '<img referrerpolicy="origin" src="https://trustseal.enamad.ir/logo.aspx'
    '?id=64418&amp;Code=4o1tQMcRX45sQDkUnGiC" alt="" code="4o1tQMcRX45sQDkUnGiC"></a>'
)

CERTIFICATE_PAGE = """
<html><body>
  <div>اطلاعات کسب و کار</div>
  <span>آدرس اینترنتی: https://www.zarinpal.com</span>
  <a href="https://enamad.ir">enamad.ir</a>
  <p>zarinpal.com</p>
</body></html>
"""

REFUSAL_PAGE = "<html><body><h1>Server Error</h1></body></html>"


@pytest.fixture(autouse=True)
def isolate_cache():
    """Verification results are cached process-wide; tests must not share them."""
    clear_cache()
    yield
    clear_cache()


class Response:
    def __init__(self, status_code, text=""):
        self.status_code = status_code
        self.text = text


class Client:
    """Records requests and replays a scripted response."""

    def __init__(self, response=None, raises=None):
        self.response = response
        self.raises = raises
        self.calls = []

    async def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": params, "headers": headers or {}})
        if self.raises:
            raise self.raises
        return self.response


# --- extraction, entirely offline -------------------------------------------

def test_a_real_badge_yields_its_registration():
    seal = extract_seal(f"<html><body>{REAL_BADGE}</body></html>")
    assert seal == EnamadSeal(seal_id="64418", code="4o1tQMcRX45sQDkUnGiC")


def test_the_logo_url_alone_is_enough():
    """Some sites embed only the image, with no wrapping link."""
    seal = extract_seal(
        '<img src="https://trustseal.enamad.ir/logo.aspx?id=8607&Code=MKrh33vhkzb6UNA2VDkk">'
    )
    assert seal is not None and seal.seal_id == "8607"


def test_a_page_with_no_badge_yields_nothing():
    assert extract_seal("<html><body>ordinary page</body></html>") is None
    assert extract_seal("") is None


def test_malformed_registrations_are_rejected():
    """Never forward attacker-controlled text into an outbound request."""
    for bad in [
        'href="https://trustseal.enamad.ir/?id=notanumber&Code=abcdefgh"',
        'href="https://trustseal.enamad.ir/?id=64418&Code=short"',
        'href="https://trustseal.enamad.ir/?id=64418&Code=has spaces here"',
        'href="https://trustseal.enamad.ir/?id=64418"',
        'href="https://trustseal.enamad.ir/?Code=4o1tQMcRX45sQDkUnGiC"',
    ]:
        assert extract_seal(bad) is None, bad


def test_a_lookalike_host_is_not_matched():
    assert extract_seal('href="https://trustseal.enamad.ir.evil.example/?id=1&Code=abcdefgh"') is None


# --- reading the certificate -------------------------------------------------

def test_the_certified_domain_is_read_from_the_page():
    assert certified_domain_from_page(CERTIFICATE_PAGE) == "zarinpal.com"


def test_enamads_own_domains_are_never_the_subject():
    """Otherwise every seal would appear to certify enamad.ir."""
    assert certified_domain_from_page("<p>enamad.ir enamad.ir trustseal.enamad.ir</p>") == ""


# --- verification ------------------------------------------------------------

def test_a_matching_certificate_verifies():
    client = Client(Response(200, CERTIFICATE_PAGE))
    result = asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal.com", client))
    assert result.verified
    assert result.certified_domain == "zarinpal.com"
    assert not result.refused and not result.unavailable


def test_the_suspect_host_is_sent_as_the_referer():
    """That header is the question being asked, not decoration."""
    client = Client(Response(200, CERTIFICATE_PAGE))
    asyncio.run(verify_seal(CONTROL_SEAL, "https://sub.zarinpal.com/checkout", client))
    assert client.calls[0]["headers"]["Referer"] == "https://zarinpal.com/"


def test_a_certificate_naming_another_domain_does_not_verify():
    client = Client(Response(200, CERTIFICATE_PAGE))
    result = asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal-secure-login.example", client))
    assert not result.verified
    assert result.certified_domain == "zarinpal.com"


def test_http_500_is_a_refusal_and_produces_the_negative_signal():
    """The stolen-badge case, verified against the live service."""
    client = Client(Response(500, REFUSAL_PAGE))
    result = asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal-secure-login.example", client))
    assert result.refused
    assert result.displays_unverified_seal
    assert not result.unavailable


def test_a_transport_failure_is_never_a_refusal():
    """An outage must not become an accusation against every sealed site."""
    client = Client(raises=TimeoutError("enamad unreachable"))
    result = asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal.com", client))
    assert result.unavailable
    assert not result.refused
    assert not result.displays_unverified_seal


def test_other_error_statuses_are_unavailable_not_refusals():
    for status in (403, 404, 429, 502, 503):
        client = Client(Response(status, "error"))
        result = asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal.com", client))
        assert result.unavailable, status
        assert not result.displays_unverified_seal, status


def test_a_200_naming_no_domain_is_inconclusive():
    client = Client(Response(200, "<html><body>enamad.ir</body></html>"))
    result = asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal.com", client))
    assert result.unavailable
    assert not result.displays_unverified_seal


# --- the control probe -------------------------------------------------------

def test_the_control_probe_reports_a_healthy_service():
    assert asyncio.run(service_is_answering(Client(Response(200, CERTIFICATE_PAGE)))) is True


def test_the_control_probe_reports_an_unhealthy_service():
    assert asyncio.run(service_is_answering(Client(Response(500, REFUSAL_PAGE)))) is False
    assert asyncio.run(service_is_answering(Client(raises=OSError("down")))) is False


# --- caching -----------------------------------------------------------------

def test_a_definite_answer_is_cached_and_not_re_requested():
    client = Client(Response(200, CERTIFICATE_PAGE))
    first = asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal.com", client))
    second = asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal.com", client))
    assert first.verified and second.verified
    assert len(client.calls) == 1, "the second lookup should have been served from cache"


def test_an_unavailable_result_is_never_cached():
    """eNamad is intermittent; a failure must not stick for an hour."""
    failing = Client(raises=TimeoutError("blip"))
    assert asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal.com", failing)).unavailable
    recovered = Client(Response(200, CERTIFICATE_PAGE))
    assert asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal.com", recovered)).verified
    assert len(recovered.calls) == 1


def test_the_cache_key_includes_the_host():
    """One seal presented from two hosts must not share an answer."""
    client = Client(Response(200, CERTIFICATE_PAGE))
    good = asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal.com", client))
    stolen = asyncio.run(verify_seal(CONTROL_SEAL, "zarinpal-login.example", client))
    assert good.verified and not stolen.verified
    assert len(client.calls) == 2


# --- circuit breaker -------------------------------------------------------
# eNamad is not routable from every network. Without a breaker each uncertain
# review carrying a badge waits the full timeout to learn nothing, because
# "unreachable" is deliberately not an answer and so is never cached.

class _AlwaysDown:
    def __init__(self) -> None:
        self.calls = 0

    async def get(self, *args, **kwargs):
        self.calls += 1
        raise OSError("no route to host")


def test_an_unreachable_registry_stops_being_asked(monkeypatch):
    import asyncio

    from persianphish_detector import enamad

    enamad.clear_cache()
    enamad.reset_breaker()
    client = _AlwaysDown()

    async def run() -> None:
        for index in range(8):
            # A different seal each time, so the answer cache cannot mask this.
            seal = enamad.EnamadSeal(seal_id=str(1000 + index), code="a" * 20)
            result = await enamad.verify_seal(seal, "example.ir", client, timeout_s=0.1)
            assert result.unavailable is True
            assert result.verified is False
            # The outcome never changes; only the cost does.
            assert result.displays_unverified_seal is False

    asyncio.run(run())
    assert client.calls == enamad._BREAKER_THRESHOLD, (
        "after the threshold the registry should not be contacted again"
    )
    enamad.reset_breaker()


def test_the_breaker_reopens_after_the_cooldown(monkeypatch):
    import asyncio

    from persianphish_detector import enamad

    enamad.clear_cache()
    enamad.reset_breaker()
    client = _AlwaysDown()

    async def run() -> None:
        for index in range(enamad._BREAKER_THRESHOLD):
            await enamad.verify_seal(
                enamad.EnamadSeal(seal_id=str(2000 + index), code="b" * 20),
                "example.ir", client, timeout_s=0.1,
            )
        assert client.calls == enamad._BREAKER_THRESHOLD
        # Pretend the cooldown elapsed; one probe must be let through so a
        # recovered registry is noticed rather than ignored forever.
        enamad._breaker["opened_at"] -= enamad._BREAKER_COOLDOWN_S + 1
        await enamad.verify_seal(
            enamad.EnamadSeal(seal_id="2999", code="c" * 20),
            "example.ir", client, timeout_s=0.1,
        )
        assert client.calls == enamad._BREAKER_THRESHOLD + 1

    asyncio.run(run())
    enamad.reset_breaker()
