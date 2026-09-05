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


# --------------------------------------------------- corroboration ownership ---

from persianphish_detector.agent import AgentReview
from persianphish_detector.orchestrator import Detector
from persianphish_detector.types import CrawlEvidence, CrawlStatus, Verdict


def _review(reasons: list[str]) -> AgentReview:
    return AgentReview(
        analysis_id="a", verdict_candidate="phishing", risk_score=0.95,
        confidence=0.93, reasons=reasons,
    )


#: Features of a brand-impersonation page: nothing the detector can see is
#: alarming. The form posts nowhere (the inputs are readonly), the host carries
#: no confusable, and the tokens are ordinary. All the evidence lives in the
#: relationship between the title and the domain, which the reviewer resolves
#: and the detector has no feature for.
_QUIET_FEATURES = {
    "external_form_action_count": 0.0,
    "suspicious_token_count": 0.0,
    "password_input_count": 0.0,
    "title_domain_token_overlap": 0.0,
}


def _evidence() -> CrawlEvidence:
    # usable means status OK *and* html present; an empty body is a failed crawl.
    return CrawlEvidence(
        target_url="https://not-filimo.example/",
        final_url="https://not-filimo.example/",
        status=CrawlStatus.OK,
        http_status=200,
        html="<html><body><p>a page</p></body></html>",
    )


def test_the_reviewers_concrete_support_is_accepted_as_corroboration() -> None:
    """The detector used to demand it rediscover risk it has no features for.

    Measured on nine live impersonation pages: every one was resolved by the
    reviewer as two_pass_phishing_with_concrete_support and reported by the
    detector as suspicious.
    """
    verdict, reasons = Detector._reconcile_agent(
        _review(["two_pass_phishing_with_concrete_support"]),
        _QUIET_FEATURES, 0.34, _evidence(),
    )
    assert verdict is Verdict.PHISHING
    assert "agent_advisory_phishing_corroborated" in reasons


def test_a_phishing_call_without_concrete_support_still_abstains() -> None:
    """Only the reviewer's evidence-backed finding carries this weight.

    Two passes agreeing is a model opinion; the reason code above is only set
    after a deterministic signal is present as well.
    """
    verdict, reasons = Detector._reconcile_agent(
        _review(["conservative_reconciliation_abstained"]),
        _QUIET_FEATURES, 0.34, _evidence(),
    )
    assert verdict is Verdict.SUSPICIOUS
    assert "agent_advisory_abstained" in reasons


def test_the_ensemble_score_cannot_veto_a_clearance() -> None:
    """A high combined score is the models finding a page unusual.

    A large modern site is unusual: hidden forms, obfuscated bundles and shadow
    roots are its ordinary furniture. google.com scores 0.898 on exactly those,
    and was reported suspicious even though both passes called it legitimate and
    recognised the host as Google's own domain. Letting the score veto the
    clearance meant the agent could never rescue the sites it was best placed to
    recognise.
    """
    from persianphish_detector.orchestrator import _observed_risk

    quiet = {
        "external_form_action_count": 0.0,
        "suspicious_token_count": 0.0,
        "password_input_count": 0.0,
        "title_domain_token_overlap": 0.0,
    }
    assert not _observed_risk(quiet), "nothing was observed on the page"

    review = AgentReview(
        analysis_id="a", verdict_candidate="legitimate", risk_score=0.0,
        confidence=0.94, reasons=["brand_recognised_as_official_domain"],
    )
    verdict, reasons = Detector._reconcile_agent(review, quiet, 0.90, _evidence())
    assert verdict is Verdict.LEGITIMATE
    assert "agent_advisory_legitimate_corroborated" in reasons


def test_observed_risk_still_blocks_a_clearance() -> None:
    """What was seen on the page keeps its veto."""
    from persianphish_detector.orchestrator import _observed_risk

    noisy = {
        "external_form_action_count": 1.0,
        "suspicious_token_count": 0.0,
        "password_input_count": 0.0,
        "title_domain_token_overlap": 0.0,
    }
    assert _observed_risk(noisy)
    review = AgentReview(
        analysis_id="a", verdict_candidate="legitimate", risk_score=0.0,
        confidence=0.94, reasons=["brand_recognised_as_official_domain"],
    )
    verdict, _ = Detector._reconcile_agent(review, noisy, 0.10, _evidence())
    assert verdict is Verdict.SUSPICIOUS
