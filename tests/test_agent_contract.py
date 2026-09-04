"""The detector's evidence-code allowlist must track the reviewer's taxonomy.

A code the reviewer emits but the detector does not know is not skipped. It
fails validation, the whole agent result is discarded as
agent_result_unsupported_code, and the detector falls back to agent_unavailable
— so one unknown string silently disables the entire agent for that page.

That is exactly what happened when the reviewer gained deceptive_link_target in
1.6.0 and known_brand_domain_mismatch in 1.8.0: verdicts were correct, complete,
and thrown away on arrival.

The expected set below is the reviewer's EvidenceCode enum. The detector cannot
import it — separate services, separate images — so it is duplicated here on
purpose, and this test is what makes the duplication safe.
"""

from __future__ import annotations

from persianphish_detector.agent import ALLOWED_EVIDENCE_CODES


REVIEWER_EVIDENCE_CODES = {
    "punycode_hostname",
    "unicode_confusable",
    "trust_word_in_hostname",
    "cross_domain_redirect",
    "credential_fields",
    "otp_fields",
    "payment_fields",
    "pii_fields",
    "external_form_action",
    "hidden_form",
    "hidden_iframe",
    "shadow_dom",
    "decoy_form",
    "captcha",
    "oauth_consent",
    "mfa_fatigue",
    "qr_code",
    "executable_link",
    "obfuscated_script",
    "anti_bot_script",
    "external_script_endpoint",
    "reference_host_mismatch",
    "reference_security_signal_mismatch",
    "reference_form_mismatch",
    "reference_embedded_media_mismatch",
    "reference_favicon_mismatch",
    "high_reference_similarity_domain_mismatch",
    "brand_token_domain_mismatch",
    "suspicious_download_prompt",
    "deceptive_link_target",
    "known_brand_domain_mismatch",
}


def test_every_code_the_reviewer_emits_is_accepted() -> None:
    missing = REVIEWER_EVIDENCE_CODES - ALLOWED_EVIDENCE_CODES
    assert not missing, (
        "the reviewer can emit these and the detector would reject its whole "
        f"verdict: {sorted(missing)}"
    )


def test_the_detector_accepts_nothing_the_reviewer_cannot_send() -> None:
    """Not harmful, but it means the two lists have drifted and one is stale."""
    extra = ALLOWED_EVIDENCE_CODES - REVIEWER_EVIDENCE_CODES
    assert not extra, f"accepted but never emitted: {sorted(extra)}"
