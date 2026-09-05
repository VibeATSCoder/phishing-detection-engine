"""Hosts this service will clear without inspecting the page.

An allowlist is the bluntest instrument here and the easiest to get dangerously
wrong, so the rules it follows are narrow on purpose.

Matching is on the registrable domain, exactly or as a subdomain of one. Never a
substring: "google.com.verify-login.ir" contains google.com and is an attack, so
anything doing containment would clear the very thing this product exists to
catch. A host carrying punycode is refused outright, because a homograph of an
entry is exactly what a lookalike is.

What it buys is worth the care. These domains are visited constantly, they are
never the phishing site, and every one of them costs a crawl, a model pass and
two LLM calls to reach the answer already known. It also answers for sites whose
crawler defences make the ordinary path fail — stackoverflow.com returns 403 to
the crawler and was reported crawl_failed, which reads to a user as the product
being broken.

Entries are for organisations of a size where impersonation is the realistic
threat and self-hosting a phishing page is not. Adding a domain here is a
decision to stop looking at it, so it wants the same scrutiny as removing a
detection rule.
"""

from __future__ import annotations

import os
from pathlib import Path

from .url_utils import UnsafeURL, hostname, registrable_domain


CATALOG_VERSION = "allowlist-20260905-v3"


#: Iranian services whose users are the target of the campaigns this detects.
_IRANIAN = {
    # media and entertainment
    "filimo.com", "aparat.com", "namava.ir", "telewebion.com", "varzesh3.com",
    # marketplaces and classifieds
    "digikala.com", "divar.ir", "torob.com", "basalam.com", "sheypoor.com",
    "alibaba.ir", "snapp.ir", "snappfood.ir", "snapp.market", "tapsi.ir",
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
#: are both the most impersonated names and the ones whose customers lose most
#: when a clone is not caught. Every entry covers its subdomains, which is what
#: matters here: the login lives at ib.<bank>, the card portal at another, and
#: enumerating them would go stale within a quarter.
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


#: Whole namespaces, cleared for every host inside them.
#:
#: This is a far stronger claim than an entry above and only holds where the
#: namespace is closed. gov.ir is administered by the Iranian government and
#: cannot be registered at will, so "some host under gov.ir" is already a
#: statement about who operates it. A registry anyone can buy from — .ir itself,
#: or .com — would be the opposite, and clearing one would disable this service
#: for a third of the web.
#:
#: Matching is on label boundaries. "gov.ir.verify-login.example" ends with the
#: text but is a different namespace entirely, and is refused.
ALLOWLISTED_SUFFIXES: frozenset[str] = frozenset({
    "gov.ir",
})


def _extra_domains() -> frozenset[str]:
    """Operator additions, one registrable domain per line.

    Kept separate from the catalog above so a deployment can extend the list
    without editing the image, and so the two are distinguishable when auditing
    why something was cleared.
    """
    path = os.getenv("PPD_ALLOWLIST_FILE", "").strip()
    if not path:
        return frozenset()
    try:
        text = Path(path).read_text(encoding="utf-8")
    except OSError:
        return frozenset()
    return frozenset(
        line.strip().lower()
        for line in text.splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def allowlisted_domain(url: str) -> str | None:
    """The allowlisted domain this URL belongs to, or None.

    Returns the entry rather than a boolean so the caller can record which one
    matched, which is what makes a wrong clearance traceable to a line in a
    list rather than to "the allowlist".
    """
    # A URL this service cannot even parse is certainly not on a list of
    # well-known sites, and a helper that raises on bad input invites a caller
    # to forget the try. hostname() rejects an empty URL and a malformed IDN by
    # raising, so both are answered here as "not allowlisted".
    try:
        host = hostname(url).lower().rstrip(".")
    except UnsafeURL:
        return None
    if not host:
        return None
    # A punycode label is how a lookalike is spelled. Refuse before matching:
    # an entry can never legitimately need one, and the check costs nothing.
    if "xn--" in host:
        return None
    # A closed namespace first: every host inside it is covered, so there is
    # nothing to enumerate.
    for suffix in ALLOWLISTED_SUFFIXES:
        if host == suffix or host.endswith("." + suffix):
            return suffix

    candidates = ALLOWLISTED_DOMAINS | _extra_domains()
    registrable = registrable_domain(host)
    if registrable in candidates:
        return registrable
    # A subdomain of an entry: mail.google.com belongs to google.com. Matched
    # on label boundaries so notgoogle.com cannot pass as google.com.
    for entry in candidates:
        if host == entry or host.endswith("." + entry):
            return entry
    return None
