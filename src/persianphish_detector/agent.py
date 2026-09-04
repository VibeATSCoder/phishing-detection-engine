from __future__ import annotations

import asyncio
import hashlib
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional, Sequence
from urllib.parse import urlsplit


ALLOWED_AGENT_VERDICTS = {"legitimate", "phishing", "suspicious", "crawl_failed"}
ALLOWED_JOB_STATUSES = {
    "queued",
    "validating",
    "ingesting",
    "crawling",
    "extracting",
    "comparing",
    "analyzing",
    "verifying",
    "reconciling",
    "completed",
    "failed",
}
ALLOWED_INTENT_CODES = {
    "credential_theft",
    "brand_impersonation",
    "malware_distribution",
    "personal_information_harvesting",
}
ALLOWED_TECHNIQUE_CODES = {
    "url_manipulation",
    "brand_visual_mimicry",
    "html_dom_structure_changes",
    "anti_bot_conditional_display",
    "multi_stage_qr_delivery",
    "authentication_permission_scenarios",
    "complementary_baseline_methods",
}
ALLOWED_EVIDENCE_CODES = {
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
    # Added by the reviewer after this list was written. A code missing here is
    # not ignored — _bounded_codes rejects the whole agent result with
    # agent_result_unsupported_code, so the reviewer's entire verdict is thrown
    # away and the detector reports agent_unavailable. deceptive_link_target
    # shipped in reviewer 1.6.0 and silently did exactly that on every page it
    # fired for; tests/test_agent_contract.py now pins the two lists together.
    "deceptive_link_target",
    "known_brand_domain_mismatch",
}
SENSITIVE_RESULT_KEYS = {
    "html",
    "raw_html",
    "suspect_html",
    "provided_html",
    "reference_html",
    "screenshot",
    "visible_text",
    "visible_text_excerpt",
    "untrusted_visible_text",
    "cookies",
    "headers",
    "form_values",
    "api_key",
}
MAX_SUSPECT_HTML_BYTES = 5_000_000
MAX_REFERENCE_HTML_BYTES = 2_000_000
MAX_TOTAL_REFERENCE_HTML_BYTES = 5_000_000
MAX_RESPONSE_BYTES = 1_000_000
SAFE_REASON_CODE = re.compile(r"^[A-Za-z0-9_.:-]{1,80}$")
SAFE_ANALYSIS_ID = re.compile(r"^[A-Za-z0-9]{1,64}$")


class AgentServiceError(RuntimeError):
    def __init__(self, code: str) -> None:
        self.code = re.sub(r"[^a-z0-9_.-]", "_", str(code).lower())[:120] or "agent_service_error"
        super().__init__(self.code)


@dataclass(frozen=True)
class AgentReview:
    analysis_id: str
    verdict_candidate: str
    risk_score: Optional[float]
    confidence: float
    evidence_codes: list[str] = field(default_factory=list)
    intent_codes: list[str] = field(default_factory=list)
    technique_group_codes: list[str] = field(default_factory=list)
    reasons: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    model: str = ""

    def audit_summary(self) -> Dict[str, Any]:
        return {
            "analysis_id": self.analysis_id,
            "verdict_candidate": self.verdict_candidate,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "evidence_codes": list(self.evidence_codes),
            "intent_codes": list(self.intent_codes),
            "technique_group_codes": list(self.technique_group_codes),
            "reasons": list(self.reasons),
            "limitations": list(self.limitations),
            "model": self.model,
        }


def _contains_sensitive_key(value: Any) -> bool:
    if isinstance(value, Mapping):
        return any(
            str(key).lower() in SENSITIVE_RESULT_KEYS or _contains_sensitive_key(item)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_contains_sensitive_key(item) for item in value)
    return False


def _bounded_codes(value: Any, allowed: set[str], *, limit: int) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise AgentServiceError("agent_result_invalid_codes")
    result: list[str] = []
    for item in value:
        code = str(item)
        if code not in allowed:
            raise AgentServiceError("agent_result_unsupported_code")
        if code not in result:
            result.append(code)
    return result


def _bounded_strings(value: Any, *, limit: int, item_limit: int) -> list[str]:
    if not isinstance(value, list) or len(value) > limit:
        raise AgentServiceError("agent_result_invalid_strings")
    result: list[str] = []
    for item in value:
        text = str(item)
        if not text or len(text) > item_limit:
            raise AgentServiceError("agent_result_invalid_string")
        if text not in result:
            result.append(text)
    return result


def _finite_probability(value: Any, *, nullable: bool = False) -> Optional[float]:
    if value is None and nullable:
        return None
    if isinstance(value, bool):
        raise AgentServiceError("agent_result_invalid_probability")
    try:
        number = float(value)
    except (TypeError, ValueError) as exc:
        raise AgentServiceError("agent_result_invalid_probability") from exc
    if not 0.0 <= number <= 1.0:
        raise AgentServiceError("agent_result_invalid_probability")
    return number


def _validated_references(references: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    if len(references) > 3:
        raise AgentServiceError("agent_reference_limit")
    allowed_keys = {
        "reference_id",
        "official_url",
        "html",
        "retrieval_score",
        "brand_name",
        "retrieved_at",
        "content_sha256",
    }
    result: list[dict[str, Any]] = []
    total_bytes = 0
    seen_ids: set[str] = set()
    for reference in references:
        unknown = set(reference) - allowed_keys
        if unknown:
            raise AgentServiceError("agent_reference_unknown_field")
        reference_id = str(reference.get("reference_id", ""))
        official_url = str(reference.get("official_url", ""))
        html = reference.get("html")
        if not reference_id or len(reference_id) > 128 or reference_id in seen_ids:
            raise AgentServiceError("agent_reference_invalid_id")
        if not official_url or len(official_url) > 8192 or not isinstance(html, str):
            raise AgentServiceError("agent_reference_invalid")
        html_bytes = len(html.encode("utf-8", errors="replace"))
        if html_bytes > MAX_REFERENCE_HTML_BYTES:
            raise AgentServiceError("agent_reference_html_too_large")
        total_bytes += html_bytes
        if total_bytes > MAX_TOTAL_REFERENCE_HTML_BYTES:
            raise AgentServiceError("agent_reference_total_too_large")
        retrieval_score = _finite_probability(reference.get("retrieval_score"))
        item: dict[str, Any] = {
            "reference_id": reference_id,
            "official_url": official_url,
            "html": html,
            "retrieval_score": retrieval_score,
        }
        for optional in ("brand_name", "retrieved_at", "content_sha256"):
            value = reference.get(optional)
            if value is not None:
                item[optional] = value
        declared_hash = item.get("content_sha256")
        if declared_hash is not None:
            if not re.fullmatch(r"[a-fA-F0-9]{64}", str(declared_hash)):
                raise AgentServiceError("agent_reference_invalid_hash")
            actual_hash = hashlib.sha256(html.encode("utf-8", errors="replace")).hexdigest()
            if actual_hash.lower() != str(declared_hash).lower():
                raise AgentServiceError("agent_reference_hash_mismatch")
        seen_ids.add(reference_id)
        result.append(item)
    return result


class AgentClient:
    """Typed client for the standalone asynchronous agentic review service."""

    def __init__(
        self,
        base_url: str,
        *,
        api_key: str = "",
        timeout_s: float = 60.0,
        poll_interval_s: float = 0.25,
        request_timeout_s: float = 10.0,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        if self.base_url:
            parsed = urlsplit(self.base_url)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.hostname
                or parsed.username
                or parsed.password
                or parsed.query
                or parsed.fragment
                or parsed.path not in {"", "/"}
            ):
                raise ValueError("invalid_agent_base_url")
        self.api_key = api_key
        self.timeout_s = max(0.05, float(timeout_s))
        self.poll_interval_s = max(0.01, float(poll_interval_s))
        self.request_timeout_s = max(0.05, min(float(request_timeout_s), self.timeout_s))
        self._client: Any = None

    def _headers(self) -> dict[str, str]:
        headers = {"accept": "application/json"}
        if self.api_key:
            headers["x-api-key"] = self.api_key
        return headers

    def _http(self):
        if self._client is None:
            import httpx

            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers=self._headers(),
                timeout=httpx.Timeout(self.request_timeout_s, connect=min(3.0, self.request_timeout_s)),
                trust_env=False,
                follow_redirects=False,
                limits=httpx.Limits(max_connections=4, max_keepalive_connections=2),
            )
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def ready(self) -> bool:
        if not self.base_url:
            return False
        try:
            response = await self._http().get("/ready")
            if response.status_code != 200 or len(response.content) > MAX_RESPONSE_BYTES:
                return False
            payload = response.json()
            return isinstance(payload, dict) and payload.get("ready") is True
        except Exception:
            return False

    async def review(
        self,
        *,
        suspect_url: str,
        suspect_html: str,
        upstream: Mapping[str, Any],
        references: Sequence[Mapping[str, Any]] = (),
    ) -> AgentReview:
        if not self.base_url:
            raise AgentServiceError("agent_service_not_configured")
        if not isinstance(suspect_html, str) or not suspect_html.strip():
            raise AgentServiceError("agent_suspect_html_missing")
        if len(suspect_html.encode("utf-8", errors="replace")) > MAX_SUSPECT_HTML_BYTES:
            raise AgentServiceError("agent_suspect_html_too_large")
        reason_codes = [
            str(item)
            for item in list(upstream.get("reason_codes") or [])[:50]
            if SAFE_REASON_CODE.fullmatch(str(item))
        ]
        payload = {
            "suspect_url": suspect_url,
            "input_mode": "provided_html",
            "suspect_html": suspect_html,
            "upstream": {
                "request_id": str(upstream.get("request_id") or "")[:128] or None,
                "rf_score": upstream.get("rf_score"),
                "tcn_score": upstream.get("tcn_score"),
                "combined_score": upstream.get("combined_score"),
                "reason_codes": list(dict.fromkeys(reason_codes)),
            },
            "references": _validated_references(references),
        }
        accepted = await self._http().post("/api/v1/analyses", json=payload)
        self._check_response_size(accepted)
        if accepted.status_code != 202:
            raise AgentServiceError(f"agent_submit_http_{accepted.status_code}")
        accepted_payload = self._json_object(accepted)
        analysis_id = str(accepted_payload.get("analysis_id", ""))
        if not SAFE_ANALYSIS_ID.fullmatch(analysis_id):
            raise AgentServiceError("agent_submit_invalid_id")

        deadline = time.monotonic() + self.timeout_s
        transient_failures = 0
        while True:
            if time.monotonic() >= deadline:
                raise AgentServiceError("agent_poll_timeout")
            response = await self._http().get(f"/api/v1/analyses/{analysis_id}")
            self._check_response_size(response)
            if response.status_code in {502, 503, 504} and transient_failures < 2:
                transient_failures += 1
                await asyncio.sleep(min(self.poll_interval_s, max(0.0, deadline - time.monotonic())))
                continue
            transient_failures = 0
            if response.status_code != 200:
                raise AgentServiceError(f"agent_poll_http_{response.status_code}")
            record = self._json_object(response)
            status = str(record.get("status", ""))
            if status not in ALLOWED_JOB_STATUSES:
                raise AgentServiceError("agent_poll_invalid_status")
            if status == "failed":
                raise AgentServiceError(record.get("error_code") or "agent_workflow_failed")
            if status == "completed":
                result = record.get("result")
                if not isinstance(result, dict):
                    raise AgentServiceError("agent_result_missing")
                return self._parse_result(analysis_id, result)
            await asyncio.sleep(min(self.poll_interval_s, max(0.0, deadline - time.monotonic())))

    @staticmethod
    def _check_response_size(response: Any) -> None:
        if len(response.content) > MAX_RESPONSE_BYTES:
            raise AgentServiceError("agent_response_too_large")

    @staticmethod
    def _json_object(response: Any) -> dict[str, Any]:
        try:
            payload = response.json()
        except Exception as exc:
            raise AgentServiceError("agent_response_invalid_json") from exc
        if not isinstance(payload, dict):
            raise AgentServiceError("agent_response_invalid_schema")
        return payload

    @staticmethod
    def _parse_result(analysis_id: str, result: Mapping[str, Any]) -> AgentReview:
        if _contains_sensitive_key(result):
            raise AgentServiceError("agent_result_sensitive_payload")
        verdict = str(result.get("verdict_candidate", ""))
        if verdict not in ALLOWED_AGENT_VERDICTS:
            raise AgentServiceError("agent_result_invalid_verdict")
        risk_score = _finite_probability(result.get("risk_score"), nullable=verdict == "crawl_failed")
        if verdict == "crawl_failed" and risk_score is not None:
            raise AgentServiceError("agent_result_crawl_failed_has_risk")
        if verdict != "crawl_failed" and risk_score is None:
            raise AgentServiceError("agent_result_missing_risk")
        confidence = _finite_probability(result.get("confidence"))
        assert confidence is not None
        model = str(result.get("model", ""))
        if len(model) > 200:
            raise AgentServiceError("agent_result_invalid_model")
        return AgentReview(
            analysis_id=analysis_id,
            verdict_candidate=verdict,
            risk_score=risk_score,
            confidence=confidence,
            evidence_codes=_bounded_codes(result.get("evidence_codes", []), ALLOWED_EVIDENCE_CODES, limit=40),
            intent_codes=_bounded_codes(result.get("intent_codes", []), ALLOWED_INTENT_CODES, limit=4),
            technique_group_codes=_bounded_codes(
                result.get("technique_group_codes", []), ALLOWED_TECHNIQUE_CODES, limit=7
            ),
            reasons=_bounded_strings(result.get("reasons", []), limit=50, item_limit=160),
            limitations=_bounded_strings(result.get("limitations", []), limit=30, item_limit=200),
            model=model,
        )
