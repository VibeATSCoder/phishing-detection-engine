"""eNamad trust-seal detection and verification.

eNamad (نماد اعتماد الکترونیکی) is Iran's official e-commerce trust seal, issued
by the Ministry of Industry, Mine and Trade. A certified site embeds a badge
linking to ``trustseal.enamad.ir`` with a registration id and code.

Why this is worth more than any model signal
--------------------------------------------
The detector's other evidence is inference: a score, a heuristic, a model's
recall. This is a registry lookup with an authority behind it, and it is
checkable.

Crucially, eNamad enforces the binding itself. The certificate page is rendered
only for the domain the code was issued to, keyed on the request's Referer.
Measured against the live service:

    id=8607  Referer alibaba.ir      -> certificate names alibaba.ir
    id=64418 Referer zarinpal.com    -> certificate names zarinpal.com
    id=64418 Referer evil.example    -> nothing rendered at all

So copying a real site's badge markup does not transfer its certification. A
phishing page presenting a stolen seal is asking eNamad to certify a domain the
seal was not issued to, and eNamad declines.

That gives two signals of opposite sign:

    seal verifies for this host   ->  strong corroboration of legitimacy
    seal present but unverified   ->  the page displays a trust seal that does
                                      not certify it, which is worth more
                                      suspicion than no seal at all

What this does not cover
------------------------
eNamad is an e-commerce seal. News and media sites do not carry one, and their
absence means nothing — measured across nine well-known Persian sites, only
zarinpal.com and alibaba.ir exposed a seal in server-rendered HTML. The rest are
client-rendered applications whose badge appears only in a browser-rendered DOM,
so seal extraction sees more when the crawler used Chromium. Absence is never
evidence of anything.

Verification requires a network call to a third party. It is therefore opt-in,
time-boxed, and fails silent: an unreachable eNamad produces no signal in either
direction rather than a false accusation.
"""

from __future__ import annotations

import html
import re
import time
from dataclasses import dataclass
from typing import Optional
from urllib.parse import parse_qs, urlsplit

from .url_utils import registrable_domain

# The badge is embedded as a link, an image, or both. Matching the query string
# rather than a specific tag keeps this robust to the several markup variants
# eNamad has published over the years.
_SEAL_PATTERN = re.compile(
    r"trustseal\.enamad\.ir/[^\"'<>\s]*", re.IGNORECASE
)
_ID_PATTERN = re.compile(r"^\d{1,10}$")
_CODE_PATTERN = re.compile(r"^[A-Za-z0-9]{8,64}$")

VERIFY_URL = "https://trustseal.enamad.ir/"

# eNamad rejects requests that do not look like a browser following the badge.
# Sending the suspect host as the Referer is not decoration: it is the question
# being asked — "do you certify this domain?"
_BROWSER_HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/140.0 Safari/537.36"
    ),
    "Accept-Language": "fa-IR,fa;q=0.9,en;q=0.8",
}


@dataclass(frozen=True)
class EnamadSeal:
    seal_id: str
    code: str

    def verification_url(self) -> str:
        return f"{VERIFY_URL}?id={self.seal_id}&Code={self.code}"


@dataclass(frozen=True)
class EnamadResult:
    seal: Optional[EnamadSeal]
    #: eNamad rendered a certificate naming this host.
    verified: bool = False
    #: The domain the certificate names, when one was found.
    certified_domain: str = ""
    #: Verification was attempted and could not complete. Distinct from a
    #: negative result, and must never be read as one.
    unavailable: bool = False
    #: eNamad answered and declined to certify this host. Measured: it returns
    #: HTTP 500 with a fixed error page for a seal presented from a domain the
    #: code was not issued to, and HTTP 200 with the certificate otherwise.
    refused: bool = False

    @property
    def present(self) -> bool:
        return self.seal is not None

    @property
    def displays_unverified_seal(self) -> bool:
        """A seal is shown and eNamad declined to certify this host.

        Requires an actual refusal. An unreachable eNamad leaves this False,
        because "the registry did not answer" and "the registry says no" are
        different facts and only one of them is evidence.
        """
        return self.present and self.refused and not self.verified

    def audit_summary(self) -> dict[str, object]:
        return {
            "present": self.present,
            "seal_id": self.seal.seal_id if self.seal else "",
            "verified": self.verified,
            "certified_domain": self.certified_domain,
            "unavailable": self.unavailable,
            "refused": self.refused,
        }


def extract_seal(page_html: str) -> Optional[EnamadSeal]:
    """Find an eNamad badge in page HTML. Offline, no network.

    Returns the first well-formed seal. Malformed ids or codes are ignored
    rather than passed on: a value that cannot be a registration is not worth a
    network round trip, and echoing attacker-controlled text into an outbound
    URL is how a detector becomes a request forwarder.
    """
    if not page_html:
        return None
    for match in _SEAL_PATTERN.finditer(page_html):
        query = urlsplit(html.unescape(match.group(0))).query
        params = parse_qs(query)
        seal_id = (params.get("id") or [""])[0].strip()
        code = (params.get("Code") or params.get("code") or [""])[0].strip()
        if _ID_PATTERN.match(seal_id) and _CODE_PATTERN.match(code):
            return EnamadSeal(seal_id=seal_id, code=code)
    return None


def certified_domain_from_page(page_text: str) -> str:
    """Read the certified domain out of a rendered certificate page.

    eNamad's own domains are excluded: the page naturally references them, and
    treating one as the certificate subject would certify every seal for
    enamad.ir.
    """
    stripped = re.sub(r"<script.*?</script>|<style.*?</style>", " ", page_text, flags=re.S | re.I)
    text = html.unescape(re.sub(r"<[^>]+>", " ", stripped))
    counts: dict[str, int] = {}
    for candidate in re.findall(
        r"\b(?:https?://)?(?:www\.)?([a-z0-9-]{2,63}(?:\.[a-z0-9-]{2,63})+)\b", text, re.IGNORECASE
    ):
        domain = candidate.lower()
        if domain.endswith("enamad.ir") or domain in {"enamad.ir", "ecsw.ir"}:
            continue
        counts[domain] = counts.get(domain, 0) + 1
    if not counts:
        return ""
    return max(counts, key=lambda key: counts[key])


# eNamad is intermittent: the same request was observed returning a certificate,
# then failing, then succeeding again minutes later. Repeating it per detection
# would both amplify that flakiness and put avoidable load on a third party, so
# confirmed answers are held briefly. Only definite answers are cached —
# a verification and a refusal. An `unavailable` is not an answer and is retried.
_CACHE: dict[tuple[str, str], tuple[float, "EnamadResult"]] = {}
_CACHE_TTL_S = 3600.0
_CACHE_MAX = 4096


def _cache_get(key: tuple[str, str]) -> Optional["EnamadResult"]:
    entry = _CACHE.get(key)
    if entry is None:
        return None
    stored_at, result = entry
    if time.monotonic() - stored_at > _CACHE_TTL_S:
        _CACHE.pop(key, None)
        return None
    return result


def _cache_put(key: tuple[str, str], result: "EnamadResult") -> None:
    if result.unavailable:
        return
    if len(_CACHE) >= _CACHE_MAX:
        _CACHE.clear()
    _CACHE[key] = (time.monotonic(), result)


# The registry is intermittent by nature and, on some networks, simply not
# routable. Without a breaker each uncertain review with a badge waits the full
# timeout to learn nothing, because "unreachable" is deliberately not an answer.
# After a run of consecutive failures, stop asking for a while.
_BREAKER_THRESHOLD = 3
_BREAKER_COOLDOWN_S = 300.0
_breaker: dict[str, float] = {"failures": 0.0, "opened_at": 0.0}


def _breaker_open() -> bool:
    if _breaker["failures"] < _BREAKER_THRESHOLD:
        return False
    if time.monotonic() - _breaker["opened_at"] >= _BREAKER_COOLDOWN_S:
        # Let one request through to find out whether it came back.
        _breaker["failures"] = 0.0
        return False
    return True


def _record_unreachable() -> None:
    _breaker["failures"] += 1
    if _breaker["failures"] == _BREAKER_THRESHOLD:
        _breaker["opened_at"] = time.monotonic()


def _record_reachable() -> None:
    _breaker["failures"] = 0.0


def reset_breaker() -> None:
    _breaker["failures"] = 0.0
    _breaker["opened_at"] = 0.0


def clear_cache() -> None:
    _CACHE.clear()


async def verify_seal(
    seal: EnamadSeal,
    host: str,
    client,
    *,
    timeout_s: float = 8.0,
) -> EnamadResult:
    """Ask eNamad whether it certifies ``host`` for this seal.

    ``client`` is any object with an httpx-compatible ``get``. The suspect host
    is sent as the Referer, which is the question itself: eNamad renders the
    certificate only for the domain the code was issued to.

    Any failure returns ``unavailable`` rather than a negative. A third party
    being unreachable must never become evidence against a site.
    """
    domain = registrable_domain(host) or host
    key = (seal.seal_id, domain)
    cached = _cache_get(key)
    if cached is not None:
        return cached
    if _breaker_open():
        # The registry is not answering at all from this network. Verified
        # against a host with no route to it: every attempt spent the full
        # timeout and returned unavailable, which is not an answer, so each
        # uncertain review paid the wait and learned nothing. Reporting
        # unavailable immediately keeps the outcome identical and the cost zero.
        return EnamadResult(seal=seal, unavailable=True)
    try:
        response = await client.get(
            VERIFY_URL,
            params={"id": seal.seal_id, "Code": seal.code},
            headers={**_BROWSER_HEADERS, "Referer": f"https://{domain}/"},
            timeout=timeout_s,
        )
    except Exception:
        _record_unreachable()
        return EnamadResult(seal=seal, unavailable=True)
    _record_reachable()

    status = getattr(response, "status_code", 0)
    if status == 500:
        # eNamad's refusal. Confirmed by measurement: an authorised Referer
        # returns 200 with the certificate, every unauthorised one returns 500
        # with an identical error page. Callers that intend to act on a refusal
        # should first confirm the service is answering at all, with
        # service_is_answering below — otherwise an outage looks like a verdict.
        result = EnamadResult(seal=seal, refused=True)
        _cache_put(key, result)
        return result
    if status != 200:
        return EnamadResult(seal=seal, unavailable=True)

    certified = certified_domain_from_page(getattr(response, "text", "") or "")
    if not certified:
        # A 200 naming no domain is not something the live service was observed
        # to produce. Treat it as inconclusive rather than inventing a meaning.
        return EnamadResult(seal=seal, unavailable=True)
    result = EnamadResult(
        seal=seal,
        verified=registrable_domain(certified) == domain,
        certified_domain=certified,
    )
    _cache_put(key, result)
    return result


# A seal known to be live, used only to tell an outage apart from a refusal.
# If eNamad stops certifying this domain the control fails closed: the negative
# signal is suppressed, which is the safe direction.
CONTROL_SEAL = EnamadSeal(seal_id="64418", code="4o1tQMcRX45sQDkUnGiC")
CONTROL_DOMAIN = "zarinpal.com"


async def service_is_answering(client, *, timeout_s: float = 8.0) -> bool:
    """Is eNamad currently certifying a seal known to be valid?

    A refusal is only evidence if the registry is working. This makes one
    request with a control seal, so that a service outage cannot be reported as
    "this page displays a trust seal that does not certify it".
    """
    result = await verify_seal(CONTROL_SEAL, CONTROL_DOMAIN, client, timeout_s=timeout_s)
    return result.verified
