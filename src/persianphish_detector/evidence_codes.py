"""Structured evidence emitted alongside a verdict.

Why this exists
---------------
``reason_codes`` mixes two unrelated things: policy commentary such as
``calibrated_fast_policy``, and actual observations about the page such as
``punycode_hostname``. A client that wants to explain *why* a page was flagged
has to guess which strings are which, and the vocabulary is not stable enough to
key a translation table on.

This module separates them. ``derive_evidence`` returns a list of typed items
with a stable code, the surface the observation came from, and a severity. The
codes are the same vocabulary the agentic reviewer uses in its ``EvidenceCode``
enum, so an item derived locally from URL features and one returned by the
reviewer are indistinguishable to a caller — which is what lets the browser
extension render a single explanation list.

``reason_codes`` is left exactly as it was. This is additive.

Nothing here inspects page content beyond the numeric features already
extracted for the model, so it introduces no new data collection.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Mapping, Optional, Sequence


class Severity:
    """How much weight a single observation deserves on its own.

    Deliberately coarse. These describe the observation, not the verdict: a
    page can carry several HIGH items and still resolve to ``suspicious`` when
    the policy declines to corroborate them.
    """

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Source:
    """Which surface produced the observation."""

    URL = "url"
    DOM = "dom"
    NETWORK = "network"
    INTEL = "intel"
    AGENT = "agent"
    CRAWL = "crawl"


@dataclass(frozen=True)
class EvidenceItem:
    code: str
    source: str
    severity: str

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


# Severity for codes the reviewer returns. Anything absent defaults to LOW so an
# unknown or newly added reviewer code still surfaces rather than disappearing.
AGENT_CODE_SEVERITY: dict[str, str] = {
    "unicode_confusable": Severity.HIGH,
    "cross_domain_redirect": Severity.HIGH,
    "external_form_action": Severity.HIGH,
    "high_reference_similarity_domain_mismatch": Severity.HIGH,
    "brand_token_domain_mismatch": Severity.HIGH,
    "punycode_hostname": Severity.HIGH,
    "credential_fields": Severity.MEDIUM,
    "otp_fields": Severity.HIGH,
    "payment_fields": Severity.HIGH,
    "pii_fields": Severity.MEDIUM,
    "hidden_form": Severity.HIGH,
    "hidden_iframe": Severity.HIGH,
    "decoy_form": Severity.HIGH,
    "shadow_dom": Severity.MEDIUM,
    "obfuscated_script": Severity.HIGH,
    "anti_bot_script": Severity.MEDIUM,
    "external_script_endpoint": Severity.MEDIUM,
    "executable_link": Severity.HIGH,
    "suspicious_download_prompt": Severity.HIGH,
    "qr_code": Severity.MEDIUM,
    "oauth_consent": Severity.MEDIUM,
    "mfa_fatigue": Severity.MEDIUM,
    "captcha": Severity.LOW,
    "trust_word_in_hostname": Severity.MEDIUM,
    "reference_host_mismatch": Severity.HIGH,
    "reference_security_signal_mismatch": Severity.MEDIUM,
    "reference_form_mismatch": Severity.MEDIUM,
    "reference_embedded_media_mismatch": Severity.LOW,
    "reference_favicon_mismatch": Severity.LOW,
}

# Deterministic URL and DOM observations, derived from the numeric feature
# vector the model already receives. Each entry is (code, feature, threshold,
# source, severity): the item is emitted when features[feature] > threshold.
_FEATURE_RULES: tuple[tuple[str, str, float, str, str], ...] = (
    ("punycode_hostname", "has_idn_or_punycode", 0.0, Source.URL, Severity.HIGH),
    ("unicode_confusable", "unicode_confusable_count", 0.0, Source.URL, Severity.HIGH),
    ("trust_word_in_hostname", "suspicious_token_count", 0.0, Source.URL, Severity.MEDIUM),
    ("ip_address_host", "has_ip_host", 0.0, Source.URL, Severity.HIGH),
    ("nonstandard_port", "nonstandard_port", 0.0, Source.URL, Severity.MEDIUM),
    ("userinfo_in_url", "at_count", 0.0, Source.URL, Severity.HIGH),
    ("excessive_subdomains", "subdomain_count", 3.0, Source.URL, Severity.MEDIUM),
    ("long_random_token", "long_random_token_count", 0.0, Source.URL, Severity.LOW),
    ("cross_domain_redirect", "cross_domain_redirect_count", 0.0, Source.NETWORK, Severity.HIGH),
    ("external_form_action", "external_form_action_count", 0.0, Source.DOM, Severity.HIGH),
    ("credential_fields", "password_input_count", 0.0, Source.DOM, Severity.MEDIUM),
    ("hidden_form", "hidden_input_count", 2.0, Source.DOM, Severity.MEDIUM),
    ("hidden_iframe", "iframe_count", 0.0, Source.DOM, Severity.LOW),
    ("obfuscated_script", "eval_count", 0.0, Source.DOM, Severity.MEDIUM),
    ("obfuscated_script", "atob_count", 0.0, Source.DOM, Severity.MEDIUM),
    ("external_script_endpoint", "external_script_ratio", 0.5, Source.DOM, Severity.MEDIUM),
    ("meta_refresh_redirect", "meta_refresh_count", 0.0, Source.DOM, Severity.LOW),
    ("missing_transport_security", "tls_missing", 0.0, Source.NETWORK, Severity.MEDIUM),
)

# Codes whose *absence* of a positive signal is meaningful, i.e. boolean
# features where 0 rather than 1 is the observation worth reporting.
_INVERTED_RULES: tuple[tuple[str, str, str, str], ...] = (
    ("insecure_transport", "is_https", Source.NETWORK, Severity.HIGH),
)


def _numeric(features: Mapping[str, Any], key: str) -> Optional[float]:
    value = features.get(key)
    if value is None or isinstance(value, bool):
        return float(value) if isinstance(value, bool) else None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def derive_evidence(
    features: Mapping[str, Any] | None = None,
    *,
    intel_match: Any = None,
    crawl_status: str = "",
    agent_codes: Sequence[str] = (),
) -> list[dict[str, str]]:
    """Collect every observation worth showing a caller, most severe first.

    Deduplicates by code: two features can imply the same observation (``eval``
    and ``atob`` both mean an obfuscated script), and a code returned by the
    reviewer may repeat one already derived locally. The first occurrence wins,
    and rule order puts the stronger source first.
    """
    items: list[EvidenceItem] = []
    seen: set[str] = set()

    def add(code: str, source: str, severity: str) -> None:
        if code not in seen:
            seen.add(code)
            items.append(EvidenceItem(code=code, source=source, severity=severity))

    if intel_match is not None and getattr(intel_match, "verdict", "") == "phishing":
        add("known_phishing_indicator", Source.INTEL, Severity.HIGH)

    if crawl_status and crawl_status not in {"ok", "partial"}:
        add("page_not_observed", Source.CRAWL, Severity.LOW)

    if features:
        for code, feature, threshold, source, severity in _FEATURE_RULES:
            value = _numeric(features, feature)
            if value is not None and value > threshold:
                add(code, source, severity)
        for code, feature, source, severity in _INVERTED_RULES:
            value = _numeric(features, feature)
            if value is not None and value <= 0:
                add(code, source, severity)

    for code in agent_codes:
        normalized = str(code).strip().lower()
        if normalized:
            add(normalized, Source.AGENT, AGENT_CODE_SEVERITY.get(normalized, Severity.LOW))

    order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
    items.sort(key=lambda item: order.get(item.severity, 3))
    return [item.to_dict() for item in items]
