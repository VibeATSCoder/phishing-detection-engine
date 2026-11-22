from __future__ import annotations

import math
import re
import unicodedata
from html import unescape
from typing import List, Tuple

from ..types import CrawlStatus


BLOCKED_HTTP_STATUS = {401, 403, 407, 429}
VPN_ACCESS_RESTRICTED = "vpn_access_restricted"
PERSIAN_VPN_PROMPT = re.compile(
    r"^(?:لطفا\s+)?(?:vpn|وی[\s-]*پی[\s-]*ان)(?:\s+خود)?\s+را\s+"
    r"(?:خاموش|غیرفعال|غیر فعال)\s+(?:کنید|نمایید|کنین)(?!\w)"
)
ENGLISH_VPN_PROMPT = re.compile(r"^(?:please\s+)?(?:disable|turn off|disconnect from)\s+(?:your\s+)?vpn\b")
PERSIAN_WEB_ACCESS = re.compile(r"برای\s+(?:دسترسی\s+به|ورود\s+به|مشاهده)\s+(?:این\s+)?(?:وب\s*سایت|سایت|صفحه)")
ENGLISH_WEB_ACCESS = re.compile(r"\bto (?:access|visit|view) (?:this |the )?(?:website|site|page)\b")
CHALLENGE_MARKERS = (
    "access denied", "attention required", "checking your browser", "cloudflare ray id",
    "enable javascript and cookies", "forbidden", "just a moment", "security check",
    "temporarily blocked", "too many requests", "verify you are human", "web server is down",
    "proudly powered by litespeed web server",
)
ERROR_TITLE_RE = re.compile(
    r"<title[^>]*>\s*(?:40[0137]|429|50[0234]|access denied|forbidden|not found|error|service unavailable)",
    re.IGNORECASE,
)


def _visible_text(html: str) -> str:
    stripped = re.sub(r"<(script|style|noscript)\b[^>]*>.*?</\1>", " ", html, flags=re.I | re.S)
    stripped = re.sub(r"<[^>]+>", " ", stripped)
    return re.sub(r"\s+", " ", stripped).strip()


def _is_vpn_access_notice(html: str) -> bool:
    body = re.sub(r"<head\b[^>]*>.*?</head\s*>", " ", html, count=1, flags=re.I | re.S)
    if re.search(r"<(?:form|input|textarea|select|iframe)\b|<a\b[^>]*\bhref\s*=", body, re.I):
        return False
    visible = unescape(_visible_text(body))
    if len(visible) > 450:
        return False
    text = unicodedata.normalize("NFKC", visible).lower()
    text = text.translate(str.maketrans("يك", "یک"))
    text = re.sub(r"[\u0640\u064b-\u065f\u0670\u200e\u200f\u202a-\u202e\u2066-\u2069]", "", text)
    text = re.sub(r"[\s\u200c\u200d]+", " ", text).strip()
    # A short access notice begins with the directive, followed by the access
    # explanation. VPN mentions inside articles and forms are ordinary evidence.
    return len(text) <= 400 and bool(
        (PERSIAN_VPN_PROMPT.match(text) and PERSIAN_WEB_ACCESS.search(text))
        or (ENGLISH_VPN_PROMPT.match(text) and ENGLISH_WEB_ACCESS.search(text))
    )


def assess_crawl_quality(
    http_status: int | None,
    content_type: str,
    html: str,
    *,
    min_score: float = 0.55,
) -> Tuple[CrawlStatus, float, List[str]]:
    reasons: List[str] = []
    lower_type = (content_type or "").lower()
    lower_html = (html or "").lower()
    byte_count = len((html or "").encode("utf-8", errors="replace"))

    if http_status in BLOCKED_HTTP_STATUS:
        return CrawlStatus.BLOCKED, 0.0, [f"http_{http_status}"]
    if http_status is not None and http_status >= 400:
        return CrawlStatus.HTTP_ERROR, 0.0, [f"http_{http_status}"]
    if http_status is None:
        return CrawlStatus.UNREACHABLE, 0.0, ["missing_http_status"]
    if lower_type and not any(token in lower_type for token in ("text/html", "application/xhtml", "text/plain")):
        return CrawlStatus.NON_HTML, 0.0, ["non_html_content_type"]

    if ("vpn" in lower_html or "خاموش" in lower_html or "فعال" in lower_html) and _is_vpn_access_notice(html or ""):
        return CrawlStatus.BLOCKED, 0.0, [VPN_ACCESS_RESTRICTED]

    marker_hits = [marker for marker in CHALLENGE_MARKERS if marker in lower_html]
    if marker_hits and (byte_count < 50_000 or ERROR_TITLE_RE.search(html or "")):
        return CrawlStatus.BLOCKED, 0.05, ["challenge_or_error_page", *marker_hits[:2]]

    score = 0.30 if 200 <= http_status < 300 else 0.15
    if byte_count >= 2_048:
        score += min(0.20, math.log10(byte_count / 2_048 + 1) * 0.10)
    else:
        reasons.append("html_too_small")
    if re.search(r"<title\b[^>]*>\s*[^<]{2,}", html or "", re.I):
        score += 0.10
    else:
        reasons.append("missing_title")
    tag_count = len(re.findall(r"<[a-zA-Z][^>]*>", html or ""))
    if tag_count >= 20:
        score += 0.15
    else:
        reasons.append("low_tag_count")
    text_length = len(_visible_text(html or ""))
    if text_length >= 100:
        score += 0.15
    else:
        reasons.append("low_visible_text")
    if re.search(r"<(?:script|link|img|form|main|article)\b", html or "", re.I):
        score += 0.10
    else:
        reasons.append("no_page_structure")

    score = min(1.0, round(score, 4))
    status = CrawlStatus.OK if score >= min_score else CrawlStatus.PARTIAL
    if status == CrawlStatus.OK:
        reasons = [reason for reason in reasons if reason not in {"html_too_small", "low_tag_count", "low_visible_text"}]
    return status, score, reasons
