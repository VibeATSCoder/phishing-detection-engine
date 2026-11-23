"""Curated first-party hosts and URLs the detector can answer without crawling."""

from __future__ import annotations

import os
import re
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from .trusted_urls import exact_https_url
from .url_utils import UnsafeURL, normalize_url


CATALOG_VERSION = "allowlist-20261123-v7"


#: Iranian services whose users are the target of the campaigns this detects.
_IRANIAN = {
    # media and entertainment
    "filimo.com", "aparat.com", "namava.ir", "telewebion.com", "varzesh3.com",
    # marketplaces and classifieds
    "digikala.com", "divar.ir", "torob.com", "basalam.com", "sheypoor.com",
    "alibaba.ir", "snapp.ir", "snappfood.ir", "tapsi.ir",
    # exchange and payment gateways
    "shaparak.ir", "zarinpal.com", "idpay.ir", "nobitex.ir", "wallex.ir",
    "asanpardakht.ir", "behpardakht.com", "sep.ir", "irankish.com",
    "sadadpsp.ir", "pep.co.ir",
    # telecoms and post
    "irancell.ir", "mci.ir", "rightel.ir", "post.ir", "tci.ir",
    # software, news and reference
    "cafebazaar.ir", "myket.ir", "zoomit.ir", "soft98.ir",
    "p30download.ir", "p30download.com", "digiato.com", "isna.ir", "irna.ir",
    "mehrnews.com", "tasnimnews.com", "farsnews.ir",
    # education, public services and utilities. Several of these answer 403 to
    # anything that is not a browser — sanjesh.org does, and was reported
    # crawl_failed on every visit, which is the shape of failure this list
    # exists to answer.
    "sanjesh.org", "medu.ir", "irandoc.ac.ir", "iranketab.ir",
    "digikalajet.com", "eitaa.com", "bale.ai", "rubika.ir",
    "shatel.ir", "asiatech.ir", "parspack.com", "iranserver.com",
    "namasha.com", "shad.ir", "ical.ir",
}

#: International services, which appear in Persian-language phishing as the
#: impersonated brand far more often than as the host.
_INTERNATIONAL = {
    # Google and its separately registered properties
    "google.com", "gmail.com", "youtube.com", "googleusercontent.com",
    "gstatic.com", "googleapis.com", "android.com",
    # Microsoft
    "microsoft.com", "outlook.com", "live.com", "office.com", "office365.com",
    "sharepoint.com", "azure.com", "bing.com", "msn.com", "skype.com",
    "linkedin.com", "github.com",
    # Apple
    "apple.com", "icloud.com", "me.com",
    # other mail and identity
    "yahoo.com", "ymail.com", "proton.me", "protonmail.com", "zoho.com",
    "aol.com", "mail.ru", "yandex.com", "yandex.ru",
    # commerce and payment
    "amazon.com", "paypal.com", "ebay.com", "aliexpress.com", "alibaba.com",
    "stripe.com", "booking.com", "airbnb.com",
    # social and messaging
    "facebook.com", "instagram.com", "whatsapp.com", "messenger.com",
    "telegram.org", "t.me", "twitter.com", "x.com", "reddit.com",
    "discord.com", "pinterest.com", "tiktok.com", "snapchat.com",
    # developer and infrastructure
    "gitlab.com", "bitbucket.org", "stackoverflow.com", "stackexchange.com",
    "cloudflare.com", "mozilla.org", "python.org", "npmjs.com",
    "docker.com", "kernel.org", "debian.org", "ubuntu.com",
    # reference, news and media
    "wikipedia.org", "wikimedia.org", "bbc.com", "bbc.co.uk", "cnn.com",
    "nytimes.com", "reuters.com", "theguardian.com",
    "netflix.com", "spotify.com", "twitch.tv", "vimeo.com",
    # productivity and AI
    "dropbox.com", "adobe.com", "zoom.us", "slack.com", "notion.so",
    "openai.com", "anthropic.com", "claude.ai", "huggingface.co",
}

#: Iranian banks, and the central bank that supervises them.
#:
#: Banking is the highest-value target in Persian-language phishing, so these
#: are frequently impersonated. The catalog covers listed homepages.
#:
#: Provenance. Every domain below resolves. Nine of them were reachable from the
#: machine this list was assembled on and each presented a TLS certificate for
#: its own domain — bmi.ir, tejaratbank.ir, bpi.ir, middleeastbank.ir,
#: bankday.ir, cbi.ir, asanpardakht.ir, sep.ir and irankish.com, all with a
#: matching *.<domain> SAN. The remainder answer DNS but refuse connections from
#: outside Iran, so their ownership could not be confirmed the same way and
#: rests on public knowledge instead. That is a weaker basis than the rest of
#: this file and worth an owner's review before it is trusted in production: a
#: wrong entry here clears somebody else's site under a bank's name.
_IRANIAN_BANKS = {
    "cbi.ir",               # Central Bank of Iran
    "bmi.ir",               # Bank Melli Iran
    "bankmellat.ir",        # Bank Mellat
    "bsi.ir",               # Bank Saderat Iran
    "tejaratbank.ir",       # Bank Tejarat
    "banksepah.ir",         # Bank Sepah
    "bank-maskan.ir",       # Bank Maskan
    "bki.ir",               # Bank Keshavarzi
    "refah-bank.ir",        # Bank Refah Kargaran
    "postbank.ir",          # Post Bank of Iran
    "edbi.ir",              # Export Development Bank of Iran
    "bim.ir",               # Bank of Industry and Mine
    "parsian-bank.com",     # Bank Parsian
    "bpi.ir",               # Bank Pasargad
    "enbank.ir",            # Bank Eghtesad Novin
    "sb24.ir",              # Bank Saman
    "sinabank.ir",          # Bank Sina
    "karafarinbank.ir",     # Bank Karafarin
    "shahr-bank.ir",        # Bank Shahr
    "ba24.ir",              # Bank Ayandeh
    "izbank.ir",            # Iran Zamin Bank
    "tourismbank.ir",       # Tourism Bank
    "sbank.ir",             # Bank Sarmayeh
    "middleeastbank.ir",    # Middle East Bank
    "rqbank.ir",            # Resalat Qard al-Hasan Bank
    "qmb.ir",               # Mehr Iran Qard al-Hasan Bank
    "bankday.ir",           # Bank Day
}

ALLOWLISTED_DOMAINS: frozenset[str] = frozenset(
    _IRANIAN | _INTERNATIONAL | _IRANIAN_BANKS
)


_OFFICIAL_HOSTS = {
    host: domain
    for domain in ALLOWLISTED_DOMAINS
    for host in (domain, f"www.{domain}")
}
# These origins also publish pages controlled by accounts or tenants on the
# same hostname. The catalog only trusts their exact front pages.
_SHARED_CONTENT_DOMAINS = frozenset({
    "azure.com", "bitbucket.org", "discord.com", "dropbox.com", "facebook.com",
    "github.com", "gitlab.com", "googleusercontent.com", "huggingface.co",
    "instagram.com", "linkedin.com", "notion.so", "npmjs.com", "reddit.com",
    "sharepoint.com", "t.me", "telegram.org", "tiktok.com", "twitch.tv",
    "twitter.com", "vimeo.com", "x.com", "youtube.com",
})
_OFFICIAL_URLS = {
    "https://accounts.google.com/": "google.com",
    "https://mail.google.com/": "google.com",
    "https://mail.google.com/mail/u/0/": "google.com",
    "https://www.filimo.com/signin": "filimo.com",
    "https://gov.ir/": "gov.ir",
}


_GOOGLE_SEARCH_URLS = frozenset({
    "https://google.com/search",
    "https://google.com/search/",
    "https://www.google.com/search",
    "https://www.google.com/search/",
})
_GOOGLE_OUTBOUND_ROUTES = frozenset({"aclk", "amp", "imgres", "local_url", "url"})
# Search terms, results display options, and browser tracking parameters.
# Parameters outside this list can change the route and require a scan.
_GOOGLE_SEARCH_PARAMS = frozenset({
    "aqs", "biw", "bih", "client", "dpr", "ei", "fbs", "gl", "gs_lcrp", "gs_lp",
    "hl", "ie", "num", "oe", "oq", "q", "rlz", "sa", "safe", "sca_esv", "sclient",
    "source", "sourceid", "spell", "start", "sxsrf", "tbm", "uact", "udm", "ved",
})


def _is_google_search(url: str) -> bool:
    base, separator, query = url.partition("?")
    if not separator or exact_https_url(base) not in _GOOGLE_SEARCH_URLS:
        return False
    if not query.isascii() or any(ch in "#;\\" or ord(ch) <= 32 or ord(ch) == 127 for ch in query):
        return False
    try:
        pairs = parse_qsl(
            query, keep_blank_values=True, strict_parsing=True, max_num_fields=32, errors="strict",
        )
    except ValueError:
        return False
    params = dict(pairs)
    return (
        len(params) == len(pairs)
        and params.keys() <= _GOOGLE_SEARCH_PARAMS
        and bool(params.get("q", "").strip())
    )


def _extra_entries() -> frozenset[str]:
    """Operator-supplied hostnames or exact HTTPS URLs, one entry per line."""
    path = os.getenv("PPD_ALLOWLIST_FILE", "").strip()
    if not path:
        return frozenset()
    try:
        text = Path(path).read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return frozenset()
    return frozenset(
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def allowlisted_domain(url: str) -> str | None:
    """Return the catalog entry for an approved HTTPS host or route."""
    if any(ch == "\\" or ord(ch) <= 32 or ord(ch) == 127 for ch in url):
        return None
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    home = exact_https_url(f"{parsed.scheme}://{parsed.netloc}/")
    if home is None:
        return None

    exact = exact_https_url(url)
    if exact in _OFFICIAL_URLS:
        return _OFFICIAL_URLS[exact]

    host = home.removeprefix("https://").removesuffix("/")
    domain = _OFFICIAL_HOSTS.get(host)
    if domain == "google.com":
        # Google also fronts outbound links and interstitials on these hosts.
        path_parts = parsed.path.lower().strip("/").split("/")
        if (
            "%" in parsed.path
            or "//" in parsed.path
            or "." in path_parts
            or ".." in path_parts
            or path_parts[0] in _GOOGLE_OUTBOUND_ROUTES
        ):
            return None
        if path_parts[0] == "search":
            return domain if _is_google_search(url) else None
        if path_parts == [""] and exact != home:
            return None

    if domain and (domain not in _SHARED_CONTENT_DOMAINS or exact == home):
        return domain
    approved = _extra_entries()
    if any(host == entry.lower() for entry in approved):
        return host

    # Accept reviewed localized paths without decoding escaped ASCII into
    # authority, path separators, query, or fragment delimiters.
    if (
        "?" in url or "#" in url or "//" in parsed.path
        or any(part in {".", ".."} for part in parsed.path.split("/"))
        or re.search(r"%[0-7][0-9a-f]", parsed.path, re.IGNORECASE)
    ):
        return None
    try:
        key = normalize_url(url)
    except UnsafeURL:
        return None
    return host if key in approved else None
