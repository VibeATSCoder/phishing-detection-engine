from __future__ import annotations

import math
import re
import statistics
from collections import Counter
from html.parser import HTMLParser
from typing import Dict, List, Mapping, Optional, Tuple
from urllib.parse import parse_qsl, unquote, urljoin, urlsplit

from ..types import CrawlEvidence, DomainFacts
from ..url_utils import (
    confusable_count,
    cross_domain_redirect_count,
    hostname,
    is_ip_literal,
    normalize_url,
    registrable_domain,
    shannon_entropy,
    split_tokens,
    suspicious_token_count,
)


FEATURE_COLUMNS = [
    "url_length",
    "host_length",
    "registrable_domain_length",
    "subdomain_count",
    "path_length",
    "path_depth",
    "query_length",
    "query_param_count",
    "fragment_length",
    "digit_ratio",
    "special_ratio",
    "hyphen_count",
    "dot_count",
    "at_count",
    "percent_encoded_count",
    "host_entropy",
    "path_entropy",
    "token_count",
    "token_length_mean",
    "token_length_std",
    "long_random_token_count",
    "suspicious_token_count",
    "is_https",
    "has_ip_host",
    "has_idn_or_punycode",
    "unicode_confusable_count",
    "nonstandard_port",
    "repeated_character_run",
    "redirect_count",
    "cross_domain_redirect_count",
    "html_bytes_log",
    "visible_text_length_log",
    "word_count_log",
    "persian_character_ratio",
    "replacement_character_count",
    "mojibake_marker_count",
    "title_present",
    "title_length_log",
    "title_domain_token_overlap",
    "total_tags_log",
    "max_dom_depth",
    "max_siblings_log",
    "form_count",
    "password_input_count",
    "email_input_count",
    "text_input_count",
    "hidden_input_count",
    "button_count",
    "external_form_action_count",
    "form_action_cross_domain_ratio",
    "internal_link_count_log",
    "external_link_count_log",
    "external_link_ratio",
    "empty_link_count_log",
    "image_count_log",
    "iframe_count",
    "script_count_log",
    "external_script_ratio",
    "stylesheet_count_log",
    "external_stylesheet_ratio",
    "favicon_count",
    "favicon_same_domain",
    "local_asset_ratio",
    "data_uri_count_log",
    "blob_reference_count",
    "eval_count",
    "atob_count",
    "document_write_count",
    "window_location_count",
    "meta_refresh_count",
    "credential_keyword_count_log",
    "captcha_keyword_count_log",
    "network_host_count_log",
    "external_network_host_ratio",
    "has_content_security_policy",
    "has_hsts",
    "has_x_frame_options",
    "domain_age_days_log",
    "domain_age_missing",
    "dns_address_count_log",
    "dns_missing",
    "tls_days_remaining_log",
    "tls_missing",
    "popularity_rank_log",
    "popularity_missing",
]


VOID_TAGS = {
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link",
    "meta", "param", "source", "track", "wbr",
}
CREDENTIAL_WORDS = {
    "account", "auth", "bank", "confirm", "credential", "login", "oauth",
    "otp", "password", "payment", "reset", "secure", "signin", "token",
    "verify", "wallet", "\u0631\u0645\u0632", "\u0648\u0631\u0648\u062f", "\u062d\u0633\u0627\u0628", "\u0628\u0627\u0646\u06a9", "\u062a\u0627\u06cc\u06cc\u062f",
}
CAPTCHA_WORDS = {"captcha", "recaptcha", "turnstile", "hcaptcha", "robot", "\u0631\u0628\u0627\u062a", "\u06a9\u067e\u0686\u0627"}


def _safe_ratio(left: float, right: float) -> float:
    return float(left) / float(right) if right else 0.0


def _log1p(value: float | int | None) -> float:
    return math.log1p(max(float(value or 0), 0.0))


def _domain_of_url(value: str) -> str:
    try:
        return registrable_domain(hostname(value))
    except Exception:
        return ""


class PageCollector(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.base_domain = _domain_of_url(base_url)
        self.tags: Counter[str] = Counter()
        self.total_tags = 0
        self.stack: List[str] = []
        self.children: List[int] = []
        self.max_depth = 0
        self.max_siblings = 0
        self.text_parts: List[str] = []
        self.title_parts: List[str] = []
        self.internal_links = 0
        self.external_links = 0
        self.empty_links = 0
        self.form_count = 0
        self.external_form_actions = 0
        self.hidden_inputs = 0
        self.password_inputs = 0
        self.email_inputs = 0
        self.text_inputs = 0
        self.button_count = 0
        self.script_count = 0
        self.external_scripts = 0
        self.stylesheet_count = 0
        self.external_stylesheets = 0
        self.favicons: List[str] = []
        self.asset_references = 0
        self.local_assets = 0
        self.meta_refresh = 0

    def feed_safely(self, html: str) -> None:
        try:
            self.feed(html)
            self.close()
        except Exception:
            pass

    @staticmethod
    def _attrs(attrs: List[Tuple[str, Optional[str]]]) -> Dict[str, str]:
        return {str(key).lower(): value or "" for key, value in attrs}

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self._start(tag, attrs, empty=False)

    def handle_startendtag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        self._start(tag, attrs, empty=True)

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag not in self.stack:
            return
        while self.stack:
            current = self.stack.pop()
            self.children.pop()
            if current == tag:
                break

    def handle_data(self, data: str) -> None:
        if not data or not data.strip():
            return
        if self.stack and self.stack[-1] == "title":
            self.title_parts.append(data.strip())
        if not any(tag in {"script", "style", "noscript", "template"} for tag in self.stack):
            self.text_parts.append(data.strip())

    def _start(self, tag: str, attrs: List[Tuple[str, Optional[str]]], empty: bool) -> None:
        tag = tag.lower()
        values = self._attrs(attrs)
        self.tags[tag] += 1
        self.total_tags += 1
        if self.children:
            self.children[-1] += 1
            self.max_siblings = max(self.max_siblings, self.children[-1])
        self._collect(tag, values)
        if not empty and tag not in VOID_TAGS:
            self.stack.append(tag)
            self.children.append(0)
            self.max_depth = max(self.max_depth, len(self.stack))

    def _collect(self, tag: str, attrs: Mapping[str, str]) -> None:
        src = attrs.get("src", "").strip()
        href = attrs.get("href", "").strip()
        for value in (src, href):
            if value and not value.lower().startswith(("data:", "blob:", "javascript:", "mailto:", "tel:", "#")):
                self.asset_references += 1
                target = urljoin(self.base_url, value)
                if _domain_of_url(target) == self.base_domain:
                    self.local_assets += 1
        if tag == "a":
            self._link(href)
        elif tag == "form":
            self.form_count += 1
            action = attrs.get("action", "").strip()
            if action and _domain_of_url(urljoin(self.base_url, action)) != self.base_domain:
                self.external_form_actions += 1
        elif tag == "input":
            kind = attrs.get("type", "text").lower()
            if kind == "hidden":
                self.hidden_inputs += 1
            elif kind == "password":
                self.password_inputs += 1
            elif kind == "email":
                self.email_inputs += 1
            elif kind in {"text", "search", "tel", "url", "number"}:
                self.text_inputs += 1
            if kind in {"button", "submit", "reset"}:
                self.button_count += 1
        elif tag == "button":
            self.button_count += 1
        elif tag == "script":
            self.script_count += 1
            if src and _domain_of_url(urljoin(self.base_url, src)) != self.base_domain:
                self.external_scripts += 1
        elif tag == "link":
            rel = attrs.get("rel", "").lower()
            if "stylesheet" in rel:
                self.stylesheet_count += 1
                if href and _domain_of_url(urljoin(self.base_url, href)) != self.base_domain:
                    self.external_stylesheets += 1
            if "icon" in rel and href:
                self.favicons.append(urljoin(self.base_url, href))
        elif tag == "meta" and attrs.get("http-equiv", "").lower() == "refresh":
            self.meta_refresh += 1

    def _link(self, href: str) -> None:
        lower = href.lower().strip()
        if not lower or lower.startswith(("#", "javascript:void")):
            self.empty_links += 1
            return
        if lower.startswith(("mailto:", "tel:", "javascript:")):
            return
        target_domain = _domain_of_url(urljoin(self.base_url, href))
        if target_domain == self.base_domain:
            self.internal_links += 1
        elif target_domain:
            self.external_links += 1


def collect_page(html: str, base_url: str) -> PageCollector:
    collector = PageCollector(base_url)
    try:
        from lxml import etree, html as lxml_html

        parser = lxml_html.HTMLParser(recover=True, encoding="utf-8")
        document = lxml_html.fromstring(html.encode("utf-8", errors="replace"), parser=parser)
        stack = [(document, 1, False)]
        while stack:
            element, depth, inherited_excluded = stack.pop()
            if not isinstance(element.tag, str):
                continue
            tag = element.tag.lower().split("}")[-1]
            excluded = inherited_excluded or tag in {"script", "style", "noscript", "template"}
            attrs = {str(key).lower(): str(value or "") for key, value in element.attrib.items()}
            collector.tags[tag] += 1
            collector.total_tags += 1
            collector.max_depth = max(collector.max_depth, depth)
            children = [child for child in element if isinstance(child.tag, str)]
            collector.max_siblings = max(collector.max_siblings, len(children))
            collector._collect(tag, attrs)
            if tag == "title":
                title_text = " ".join(str(item).strip() for item in element.itertext() if str(item).strip())
                if title_text:
                    collector.title_parts.append(title_text)
            if not excluded and element.text and element.text.strip():
                collector.text_parts.append(element.text.strip())
            if not excluded:
                for child in children:
                    if child.tail and child.tail.strip():
                        collector.text_parts.append(child.tail.strip())
            stack.extend((child, depth + 1, excluded) for child in reversed(children))
        return collector
    except Exception:
        collector.feed_safely(html)
        return collector


def _url_features(url: str, redirects: List[str]) -> Dict[str, float]:
    normalized = normalize_url(url)
    parsed = urlsplit(normalized)
    host = parsed.hostname or ""
    reg_domain = registrable_domain(normalized)
    labels = [label for label in host.split(".") if label]
    reg_labels = [label for label in reg_domain.split(".") if label]
    subdomain_count = max(len(labels) - len(reg_labels), 0)
    path = unquote(parsed.path or "")
    decoded = unquote(normalized)
    tokens = split_tokens(decoded)
    token_lengths = [len(token) for token in tokens]
    digits = sum(char.isdigit() for char in decoded)
    letters = sum(char.isalpha() for char in decoded)
    special = sum(not char.isalnum() for char in decoded)
    random_tokens = sum(
        len(token) >= 10 and shannon_entropy(token) >= 3.0 and not re.search(r"[aeiou\u0600-\u06ff]", token, re.I)
        for token in tokens
    )
    return {
        "url_length": len(normalized),
        "host_length": len(host),
        "registrable_domain_length": len(reg_domain),
        "subdomain_count": subdomain_count,
        "path_length": len(path),
        "path_depth": len([part for part in path.split("/") if part]),
        "query_length": len(parsed.query),
        "query_param_count": len(parse_qsl(parsed.query, keep_blank_values=True)),
        "fragment_length": 0,
        "digit_ratio": _safe_ratio(digits, max(letters + digits, 1)),
        "special_ratio": _safe_ratio(special, max(len(decoded), 1)),
        "hyphen_count": host.count("-"),
        "dot_count": host.count("."),
        "at_count": normalized.count("@"),
        "percent_encoded_count": len(re.findall(r"%[0-9A-Fa-f]{2}", normalized)),
        "host_entropy": shannon_entropy(host),
        "path_entropy": shannon_entropy(path),
        "token_count": len(tokens),
        "token_length_mean": statistics.fmean(token_lengths) if token_lengths else 0.0,
        "token_length_std": statistics.pstdev(token_lengths) if len(token_lengths) > 1 else 0.0,
        "long_random_token_count": random_tokens,
        "suspicious_token_count": suspicious_token_count(normalized),
        "is_https": float(parsed.scheme == "https"),
        "has_ip_host": float(is_ip_literal(host)),
        "has_idn_or_punycode": float("xn--" in host or any(ord(char) > 127 for char in url)),
        "unicode_confusable_count": confusable_count(url),
        "nonstandard_port": float(bool(parsed.port and parsed.port not in {80, 443})),
        "repeated_character_run": float(bool(re.search(r"(.)\1{3,}", host + path, re.I))),
        "redirect_count": max(len(redirects) - 1, 0),
        "cross_domain_redirect_count": cross_domain_redirect_count(redirects),
    }


def _html_features(evidence: CrawlEvidence) -> Dict[str, float]:
    html = evidence.html or ""
    lower_html = html.lower()
    base_url = evidence.final_url or evidence.target_url
    collector = collect_page(html, base_url)
    text = " ".join(collector.text_parts)
    title = " ".join(collector.title_parts)
    words = re.findall(r"[\w\u0600-\u06ff]+", text, re.UNICODE)
    persian_chars = re.findall(r"[\u0600-\u06ff]", text)
    domain_tokens = set(split_tokens(_domain_of_url(base_url)))
    title_tokens = set(split_tokens(title))
    total_links = collector.internal_links + collector.external_links
    external_form_ratio = _safe_ratio(collector.external_form_actions, collector.form_count)
    network_domains = [registrable_domain(host) for host in evidence.network_hosts]
    base_domain = _domain_of_url(base_url)
    external_network = sum(bool(item and item != base_domain) for item in network_domains)
    keyword_count = sum(text.lower().count(word) for word in CREDENTIAL_WORDS)
    captcha_count = sum(text.lower().count(word) for word in CAPTCHA_WORDS)
    headers = {key.lower(): value for key, value in evidence.response_headers.items()}
    html_bytes = len(html.encode("utf-8", errors="replace"))
    return {
        "html_bytes_log": _log1p(html_bytes),
        "visible_text_length_log": _log1p(len(text)),
        "word_count_log": _log1p(len(words)),
        "persian_character_ratio": _safe_ratio(len(persian_chars), max(len(text), 1)),
        "replacement_character_count": html.count("\ufffd"),
        "mojibake_marker_count": sum(html.count(marker) for marker in ("\u00d8", "\u00d9", "\u00db", "\u00c3")),
        "title_present": float(bool(title.strip())),
        "title_length_log": _log1p(len(title)),
        "title_domain_token_overlap": _safe_ratio(len(domain_tokens & title_tokens), max(len(domain_tokens), 1)),
        "total_tags_log": _log1p(collector.total_tags),
        "max_dom_depth": collector.max_depth,
        "max_siblings_log": _log1p(collector.max_siblings),
        "form_count": collector.form_count,
        "password_input_count": collector.password_inputs,
        "email_input_count": collector.email_inputs,
        "text_input_count": collector.text_inputs,
        "hidden_input_count": collector.hidden_inputs,
        "button_count": collector.button_count,
        "external_form_action_count": collector.external_form_actions,
        "form_action_cross_domain_ratio": external_form_ratio,
        "internal_link_count_log": _log1p(collector.internal_links),
        "external_link_count_log": _log1p(collector.external_links),
        "external_link_ratio": _safe_ratio(collector.external_links, total_links),
        "empty_link_count_log": _log1p(collector.empty_links),
        "image_count_log": _log1p(collector.tags["img"]),
        "iframe_count": collector.tags["iframe"] + collector.tags["frame"],
        "script_count_log": _log1p(collector.script_count),
        "external_script_ratio": _safe_ratio(collector.external_scripts, collector.script_count),
        "stylesheet_count_log": _log1p(collector.stylesheet_count),
        "external_stylesheet_ratio": _safe_ratio(collector.external_stylesheets, collector.stylesheet_count),
        "favicon_count": len(collector.favicons),
        "favicon_same_domain": float(any(_domain_of_url(item) == base_domain for item in collector.favicons)),
        "local_asset_ratio": _safe_ratio(collector.local_assets, collector.asset_references),
        "data_uri_count_log": _log1p(lower_html.count("data:")),
        "blob_reference_count": lower_html.count("blob:"),
        "eval_count": len(re.findall(r"\beval\s*\(", lower_html)),
        "atob_count": len(re.findall(r"\batob\s*\(", lower_html)),
        "document_write_count": lower_html.count("document.write"),
        "window_location_count": lower_html.count("window.location"),
        "meta_refresh_count": collector.meta_refresh,
        "credential_keyword_count_log": _log1p(keyword_count),
        "captcha_keyword_count_log": _log1p(captcha_count),
        "network_host_count_log": _log1p(len(set(evidence.network_hosts))),
        "external_network_host_ratio": _safe_ratio(external_network, len(network_domains)),
        "has_content_security_policy": float("content-security-policy" in headers),
        "has_hsts": float("strict-transport-security" in headers),
        "has_x_frame_options": float("x-frame-options" in headers),
    }


def _domain_features(facts: DomainFacts) -> Dict[str, float]:
    return {
        "domain_age_days_log": _log1p(facts.domain_age_days),
        "domain_age_missing": float(facts.domain_age_days is None),
        "dns_address_count_log": _log1p(facts.dns_address_count),
        "dns_missing": float(facts.dns_address_count is None),
        "tls_days_remaining_log": _log1p(facts.tls_days_remaining),
        "tls_missing": float(facts.tls_days_remaining is None),
        "popularity_rank_log": _log1p(facts.popularity_rank),
        "popularity_missing": float(facts.popularity_rank is None),
    }


def extract_features(evidence: CrawlEvidence, domain_facts: DomainFacts | None = None) -> Dict[str, float]:
    if not evidence.html:
        raise ValueError("usable_html_required_for_combined_features")
    facts = domain_facts or DomainFacts(registrable_domain=registrable_domain(evidence.final_url or evidence.target_url))
    features: Dict[str, float] = {}
    features.update(_url_features(evidence.final_url or evidence.target_url, evidence.redirect_chain))
    features.update(_html_features(evidence))
    features.update(_domain_features(facts))
    missing = [column for column in FEATURE_COLUMNS if column not in features]
    if missing:
        raise RuntimeError(f"feature extractor missing columns: {missing}")
    return {column: float(features[column]) for column in FEATURE_COLUMNS}


def feature_vector(features: Mapping[str, float]) -> List[float]:
    missing = [column for column in FEATURE_COLUMNS if column not in features]
    if missing:
        raise ValueError(f"missing features: {missing}")
    return [float(features[column]) for column in FEATURE_COLUMNS]
