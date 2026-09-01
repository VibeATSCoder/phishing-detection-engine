from __future__ import annotations

import ipaddress
import math
import posixpath
import re
import socket
import unicodedata
from collections import Counter
from functools import lru_cache
from typing import Iterable, List, Tuple
from urllib.parse import parse_qsl, quote, unquote, urljoin, urlsplit, urlunsplit

try:
    import idna
except ImportError:  # pragma: no cover - stdlib fallback
    idna = None

try:
    import tldextract
except ImportError:  # pragma: no cover - dependency-light fallback
    tldextract = None

_TLD_EXTRACTOR = tldextract.TLDExtract(suffix_list_urls=()) if tldextract else None


ALLOWED_SCHEMES = {"http", "https"}
MULTIPART_SUFFIXES = {
    "ac.ir", "co.ir", "gov.ir", "id.ir", "net.ir", "org.ir", "sch.ir",
    "ac.uk", "co.uk", "gov.uk", "org.uk", "com.au", "com.br", "co.jp",
}
SUSPICIOUS_TOKENS = {
    "account", "auth", "bank", "confirm", "credential", "login", "oauth",
    "password", "reset", "secure", "signin", "support", "token", "update",
    "verify", "wallet", "webscr", "invoice", "payment",
}
CYRILLIC_GREEK_CONFUSABLES = set("\u0430\u0435\u043e\u0440\u0441\u0445\u0443\u0456\u0458\u04bb\u03b1\u03b5\u03bf\u03c1\u03c7\u03bd")


class UnsafeURL(ValueError):
    pass


# Feature extraction resolves a domain for every href and src on the page, so
# these run tens of thousands of times per document and dominate the detector's
# CPU profile — idna.encode alone was 44% of extract_features. Both functions
# are pure, so caching is behaviour-preserving; the bound keeps a hostile page
# full of unique URLs from growing memory without limit. Exceptions are not
# cached, so a malformed URL is re-validated every time, which is what we want.
@lru_cache(maxsize=50_000)
def normalize_url(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        raise UnsafeURL("empty_url")
    if "://" not in raw:
        raw = "https://" + raw.lstrip("/")
    try:
        parsed = urlsplit(raw)
        host = (parsed.hostname or "").strip(".").lower()
        port = parsed.port
    except ValueError as exc:
        raise UnsafeURL("invalid_url_authority") from exc
    scheme = parsed.scheme.lower()
    if scheme not in ALLOWED_SCHEMES:
        raise UnsafeURL("unsupported_scheme")
    if parsed.username or parsed.password:
        raise UnsafeURL("userinfo_not_allowed")
    if not host:
        raise UnsafeURL("missing_hostname")
    try:
        ascii_host = idna.encode(host, uts46=True).decode("ascii") if idna else host.encode("idna").decode("ascii")
    except Exception as exc:
        raise UnsafeURL("invalid_idn_hostname") from exc
    if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        netloc = f"{ascii_host}:{port}"
    else:
        netloc = ascii_host
    path = parsed.path or "/"
    decoded_path = unquote(path, errors="replace")
    normalized_path = posixpath.normpath(decoded_path)
    if path.endswith("/") and not normalized_path.endswith("/"):
        normalized_path += "/"
    if not normalized_path.startswith("/"):
        normalized_path = "/" + normalized_path
    path = quote(normalized_path, safe="/%:@!$&'()*+,;=-._~")
    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def tcn_domain_input(value: str) -> str:
    """Return the normalized hostname used as the TCN's complete input.

    The RF and crawler intentionally retain the full URL.  The URL TCN is a
    separate lexical model and must not let an arbitrary deep path or tracking
    query replace the hostname in its fixed byte window.  Keep the full host
    (including subdomains) rather than reducing to a registrable domain, but
    remove the scheme, port, path, query, and fragment.
    """
    parsed = urlsplit(normalize_url(value))
    host = (parsed.hostname or "").lower()
    if not host:  # Defensive: normalize_url already rejects a missing host.
        raise UnsafeURL("missing_hostname")
    return host


def canonical_url(value: str) -> str:
    parsed = urlsplit(normalize_url(value))
    query = "&".join(
        f"{quote(key, safe='')}={quote(val, safe='')}"
        for key, val in sorted(parse_qsl(parsed.query, keep_blank_values=True))
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


@lru_cache(maxsize=50_000)
def hostname(value: str) -> str:
    return (urlsplit(normalize_url(value)).hostname or "").lower()


@lru_cache(maxsize=100_000)
def registrable_domain(value: str) -> str:
    host = hostname(value) if "://" in value or "/" in value else value.lower().strip(".")
    if not host or is_ip_literal(host):
        return host
    if _TLD_EXTRACTOR:
        ext = _TLD_EXTRACTOR(host)
        if ext.domain and ext.suffix:
            return f"{ext.domain}.{ext.suffix}"
    parts = host.split(".")
    if len(parts) < 2:
        return host
    last_two = ".".join(parts[-2:])
    if len(parts) >= 3 and last_two in MULTIPART_SUFFIXES:
        return ".".join(parts[-3:])
    return last_two


def is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def is_public_ip(value: str) -> bool:
    ip = ipaddress.ip_address(value)
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
        or ip.is_reserved or ip.is_unspecified
    )


def resolve_public_addresses(url: str, allow_private: bool = False) -> List[str]:
    host = hostname(url)
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)})
    except socket.gaierror as exc:
        raise UnsafeURL("dns_resolution_failed") from exc
    if not addresses:
        raise UnsafeURL("dns_no_addresses")
    if not allow_private and any(not is_public_ip(address) for address in addresses):
        raise UnsafeURL("private_or_reserved_address")
    return addresses


def safe_redirect_url(current_url: str, location: str) -> str:
    return normalize_url(urljoin(current_url, location))


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def split_tokens(text: str) -> List[str]:
    return [part.lower() for part in re.split(r"[^A-Za-z0-9\u0600-\u06ff]+", text) if part]


def confusable_count(text: str) -> int:
    return sum(char in CYRILLIC_GREEK_CONFUSABLES for char in unicodedata.normalize("NFKC", text))


def suspicious_token_count(url: str) -> int:
    return sum(token in SUSPICIOUS_TOKENS for token in split_tokens(unquote(url)))


def cross_domain_redirect_count(urls: Iterable[str]) -> int:
    domains = [registrable_domain(url) for url in urls if url]
    return sum(left != right for left, right in zip(domains, domains[1:]))
