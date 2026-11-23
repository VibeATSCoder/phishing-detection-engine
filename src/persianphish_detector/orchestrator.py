from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import sqlite3
import time
import uuid
from dataclasses import asdict, replace
from pathlib import Path
from urllib.parse import urlsplit
from typing import Any, Callable, Dict, Literal, Mapping, Optional, Sequence, Tuple, get_args

from . import __version__
from .allowlist import CATALOG_VERSION, allowlisted_domain
from .agent import AgentClient, AgentReview, AgentServiceError
from .config import DetectorConfig
from .crawl import BrowserCrawler, HttpCrawler, from_browser_payload
from .crawl.quality import VPN_ACCESS_RESTRICTED
from .domain_facts import DomainFacts, collect_domain_facts
from .enamad import extract_seal, service_is_answering, verify_seal
from .jev import DecisionThresholds, JevClient, JevFinding, apply_jev, jev_structure, screening_text
from .jev_local import LocalJev

LOGGER = logging.getLogger(__name__)


def _rf_input_features(
    features: Mapping[str, float],
    evidence: Any,
    facts: Any,
    score_origin: bool,
) -> tuple[Mapping[str, float], bool]:
    """Score the Random Forest on the origin, not the browsed URL.

    Not one of the 935 legitimate rows in the training corpus carries a URL
    path, while 153 of the 845 phishing rows do. The forest therefore only ever
    saw a path on a phishing example and learned the collection artifact rather
    than phishing: on identical page HTML, changing the final URL from
    aparat.com/ to aparat.com/home moves its probability from 0.074 to 0.962,
    and digikala.com/ to digikala.com/home from 0.035 to 0.960. Every subpage of
    every legitimate site is flagged.

    Feeding it the origin puts the input back in the distribution it was fitted
    on. Path and query risk is not discarded: `features` is still derived from
    the full URL and remains what `_deterministic_risk`, the token counts and
    the TCN read, so a hostile path on a clean origin is still caught by the
    signals that do not depend on the forest's opinion.

    Returns the features to score and whether the origin view was used.
    """
    if not score_origin:
        return features, False
    browsed = evidence.final_url or evidence.target_url or ""
    parsed = urlsplit(browsed)
    if not parsed.scheme or not parsed.netloc:
        return features, False
    origin = f"{parsed.scheme}://{parsed.netloc}/"
    if origin == browsed:
        return features, False
    if all(column in features for column in FEATURE_COLUMNS):
        return origin_features(features, origin), True
    origin_view = replace(evidence, final_url=origin, redirect_chain=[origin])
    return extract_features(origin_view, facts), True


def _observed_risk(features: Mapping[str, float]) -> bool:
    """Risk that was observed on the page rather than inferred from it.

    Every term here is a count taken from the DOM or the URL. None of them is a
    model's opinion, which is what makes them safe to let veto a clearance.
    """
    return (
        features["external_form_action_count"] > 0
        or features["suspicious_token_count"] >= 2
        or (features["password_input_count"] > 0 and features["title_domain_token_overlap"] == 0)
    )


def _deterministic_risk(features: Mapping[str, float], combined_score: float | None) -> bool:
    """Observed risk, or the ensemble putting the page above the midpoint.

    The docstring here used to claim this did not depend on any model's opinion,
    while its first term was exactly that: the ensemble's own score. That term
    meant a page the models happened to dislike could never be cleared by the
    agent no matter what the agent found — google.com scores 0.898 on features
    that are ordinary for a large site (a hidden form, an obfuscated script, a
    shadow root) and was reported suspicious even though both passes called it
    legitimate and recognised the host as Google's own domain.

    It is kept for the phishing direction, where an ensemble already over the
    midpoint is corroboration rather than an obstacle. The clearing direction
    uses _observed_risk instead.
    """
    return (combined_score is not None and combined_score >= 0.5) or _observed_risk(features)
from .features import FEATURE_COLUMNS, extract_features, origin_features
from .evidence_codes import derive_evidence
from .intel import IntelMatch, IntelStore
from .observability import METRICS, record_detection, span, url_labels
from .models import DetectorArtifact, load_artifact
from .models.tcn import ONNXTCNPredictor, TCN_INPUT_CONTRACT
from .review import ReviewStore
from .trusted_urls import TrustedResult, TrustedURLStore, exact_https_url
from .types import CrawlEvidence, CrawlStatus, DetectionResult, Verdict
from .url_utils import UnsafeURL, canonical_url, resolve_public_addresses, suspicious_token_count


PipelineStage = Literal["rf", "decision", "rag", "agent"]
PIPELINE_STAGES = get_args(PipelineStage)
ProgressCallback = Callable[[dict[str, str]], None]


def _is_terminal_crawl_failure(evidence: CrawlEvidence) -> bool:
    return evidence.http_status == 403 or VPN_ACCESS_RESTRICTED in evidence.quality_reasons


def _progress(
    callback: ProgressCallback | None, stage: str, status: str, verdict: Verdict | None = None,
) -> None:
    if callback is not None:
        event = {"type": "stage", "stage": stage, "status": status}
        if verdict is not None:
            event["verdict"] = verdict.value
        callback(event)


class Detector:
    def __init__(self, config: DetectorConfig) -> None:
        self.config = config
        self.http = HttpCrawler(
            timeout_s=config.http_timeout_s,
            attempts=config.http_attempts,
            max_bytes=config.max_html_bytes,
            max_redirects=config.max_redirects,
            allow_private_network=config.allow_private_network,
            min_quality_score=config.min_quality_score,
        )
        self.browser = BrowserCrawler(
            timeout_s=config.browser_timeout_s,
            allow_private_network=config.allow_private_network,
            min_quality_score=config.min_quality_score,
        ) if config.use_browser else None
        self.intel = IntelStore(config.intel_db_path)
        self.review = ReviewStore(config.review_db_path)
        self.trust: TrustedURLStore | None = None
        if config.trusted_urls_enabled:
            try:
                self.trust = TrustedURLStore(config.intel_db_path)
            except (OSError, sqlite3.Error) as exc:
                LOGGER.warning("trusted URL cache unavailable: %s", type(exc).__name__)
        self.artifact: Optional[DetectorArtifact] = (
            load_artifact(config.artifact_path)
            if config.fast_models_enabled and config.artifact_path.exists() else None
        )
        self.tcn: Optional[ONNXTCNPredictor] = None
        tcn_contract = (
            self.artifact.metadata.get("tcn_and_ensemble", {})
            .get("tokenizer", {})
            .get("input_contract")
            if self.artifact
            else None
        )
        if self.artifact and self.artifact.tcn_model_path and tcn_contract == TCN_INPUT_CONTRACT:
            path = Path(self.artifact.tcn_model_path)
            if not path.is_absolute():
                path = config.artifact_path.parent / path
            if path.exists():
                try:
                    self.tcn = ONNXTCNPredictor(path)
                except Exception:
                    self.tcn = None
        self.agent = AgentClient(
            config.agent_base_url,
            api_key=config.agent_api_key,
            timeout_s=config.agent_timeout_s,
            poll_interval_s=config.agent_poll_interval_s,
        ) if config.agent_base_url else None
        self.jev = JevClient(
            base_url=config.jev_base_url,
            model=config.jev_model,
            api_format=config.jev_api_format,
            api_key=config.jev_api_key,
            timeout_s=config.jev_timeout_s,
            max_text_chars=config.jev_max_text_chars,
        ) if config.jev_base_url else None
        self.jev_local = LocalJev.load(config.jev_local_model_path) if config.jev_local_model_path else None
        self._enamad_client: Any = None

    def _enamad_http(self) -> Any:
        import httpx

        if self._enamad_client is None:
            self._enamad_client = httpx.AsyncClient(
                follow_redirects=True, timeout=self.config.enamad_timeout_s
            )
        return self._enamad_client

    async def close(self) -> None:
        if self._enamad_client is not None:
            await self._enamad_client.aclose()
            self._enamad_client = None
        if self.browser:
            await self.browser.close()
        if self.agent:
            await self.agent.close()
        if self.jev:
            await self.jev.close()

    async def detect(
        self,
        url: str,
        browser_evidence: Mapping[str, Any] | None = None,
        agent_references: Sequence[Mapping[str, Any]] | None = None,
        use_jev: bool | None = None,
        *,
        use_rf: bool | None = None,
        pipeline: Sequence[PipelineStage] | None = None,
        on_progress: ProgressCallback | None = None,
        decision_thresholds: DecisionThresholds | None = None,
        use_trusted_urls: bool = True,
    ) -> DetectionResult:
        """Trace-wrapped entry point; the pipeline itself lives in ``_detect``."""
        with span("detector.detect", **url_labels(url)):
            return await self._detect(
                url, browser_evidence, agent_references, use_jev, use_rf, pipeline, on_progress,
                decision_thresholds, use_trusted_urls,
            )

    def _trust_policy(
        self, pipeline: Sequence[PipelineStage] | None, run_fast: bool, run_jev: bool,
        thresholds: DecisionThresholds | None,
    ) -> str:
        policy = thresholds or DecisionThresholds.from_config(self.config, ordered_pipeline=pipeline is not None)
        fields = (
            __version__, pipeline, run_fast, run_jev, policy.model_dump(),
            self.config.jev_base_url, self.config.jev_model, self.config.jev_api_format,
            self.config.min_quality_score, self.config.score_origin, self.config.jev_max_text_chars,
            self.config.trusted_url_min_confidence, self.config.trusted_url_max_risk,
            self.config.trusted_url_ttl_s, self.config.trusted_rag_url_ttl_s,
            self.artifact.model_version if self.artifact else None,
        )
        return hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest()

    def _trust_result(
        self, request_id: str, url: str, started: float, pipeline: Sequence[PipelineStage] | None,
        *, curated: str | None = None, cached: TrustedResult | None = None,
    ) -> DetectionResult:
        summary: dict[str, Any] = {}
        if pipeline is not None:
            summary["pipeline"] = [{"stage": stage, "status": "skipped"} for stage in pipeline]
        if cached is not None:
            stage = "trusted_url_cache"
            risk = cached.risk
            summary["trusted_url"] = asdict(cached)
            reasons = ["trusted_url_cache_hit", cached.source]
        else:
            stage = "allowlist"
            risk = 0.0
            reasons = ["host_on_allowlist", f"allowlist_entry_{curated}", CATALOG_VERSION]
        METRICS.crawl_outcomes.labels(source=stage, status="skipped").inc()
        result = self._result(
            request_id, url, url, Verdict.LEGITIMATE, risk, stage, CrawlStatus.SKIPPED,
            reasons, {"rf": None, "tcn": None}, started, summary,
        )
        self._persist(result)
        return result

    async def _remember_trust(
        self, url: str | None, policy: str | None, evidence: CrawlEvidence, result: DetectionResult,
        features: Mapping[str, float] | None,
    ) -> None:
        if self.trust is None or url is None or policy is None:
            return
        if result.verdict != Verdict.LEGITIMATE:
            try:
                await asyncio.to_thread(self.trust.forget, url)
            except sqlite3.Error:
                pass
            return
        decision = result.evidence_summary.get("jev") or {}
        confidence = decision.get("confidence")
        risk = decision.get("risk")
        if (
            features is None
            or "jev_short_circuit_legit" not in result.reason_codes
            or decision.get("status") != "completed"
            or decision.get("label") != "legitimate"
            or decision.get("gates")
            or any(step["status"] == "unavailable" for step in result.evidence_summary.get("pipeline", ()))
            or not isinstance(confidence, (float, int))
            or not isinstance(risk, (float, int))
            or not self.config.trusted_url_min_confidence <= confidence <= 1
            or not 0 <= risk <= self.config.trusted_url_max_risk
            or self.config.allow_private_network
            or not evidence.usable
            or evidence.http_status != 200
            or exact_https_url(evidence.final_url) != url
            or any(exact_https_url(hop) != url for hop in evidence.redirect_chain)
            or suspicious_token_count(url) != 0
            or features["password_input_count"] != 0
            or _observed_risk(features)
            or (result.model_scores.get("combined") or 0) >= 0.15
        ):
            return
        try:
            learned = await asyncio.to_thread(
                self.trust.remember, url, policy, risk, confidence,
                self.config.trusted_url_ttl_s, self.config.trusted_rag_url_ttl_s,
            )
        except sqlite3.Error:
            return
        result.reason_codes.append("trusted_url_cache_stored")
        result.evidence_summary["trusted_url"] = asdict(learned)

    async def _detect(
        self,
        url: str,
        browser_evidence: Mapping[str, Any] | None = None,
        agent_references: Sequence[Mapping[str, Any]] | None = None,
        use_jev: bool | None = None,
        use_rf: bool | None = None,
        pipeline: Sequence[PipelineStage] | None = None,
        on_progress: ProgressCallback | None = None,
        decision_thresholds: DecisionThresholds | None = None,
        use_trusted_urls: bool = True,
    ) -> DetectionResult:
        started = time.perf_counter()
        request_id = uuid.uuid4().hex
        run_fast = self.config.fast_models_enabled and use_rf is not False
        run_jev = self.config.jev_enabled if use_jev is None else use_jev
        try:
            normalized = canonical_url(url)
        except UnsafeURL as exc:
            invalid = DetectionResult(
                request_id=request_id,
                url=url,
                final_url="",
                verdict=Verdict.CRAWL_FAILED,
                risk_score=0.5,
                stage="input",
                crawl_status=CrawlStatus.INVALID_URL,
                reason_codes=[str(exc)],
                latency_ms={"total": (time.perf_counter() - started) * 1000},
            )
            record_detection(invalid)
            return invalid

        intel_match = self.intel.lookup(normalized)
        trust_key = exact_https_url(url) if browser_evidence is None and not agent_references else None
        policy_hash = None
        if trust_key is not None and self.trust is not None:
            policy_hash = self._trust_policy(pipeline, run_fast, run_jev, decision_thresholds)
        if intel_match:
            METRICS.intel_matches.labels(
                source=intel_match.source, verdict=intel_match.verdict
            ).inc()
        if intel_match and intel_match.verdict == "phishing":
            if trust_key is not None and self.trust is not None:
                try:
                    await asyncio.to_thread(self.trust.forget, trust_key)
                except sqlite3.Error:
                    pass
            summary = {"intel": asdict(intel_match)}
            if pipeline is not None:
                summary["pipeline"] = [{"stage": stage, "status": "skipped"} for stage in pipeline]
            result = self._result(
                request_id, normalized, normalized, Verdict.PHISHING, 1.0, "reputation",
                CrawlStatus.PARTIAL, ["exact_local_phishing_feed_match", f"intel_{intel_match.source}"],
                {"rf": None, "tcn": None}, started, summary,
                evidence_items=derive_evidence(intel_match=intel_match),
            )
            self._persist(result)
            return result

        if use_trusted_urls and self.config.trusted_urls_enabled and trust_key is not None:
            curated = allowlisted_domain(trust_key)
            if curated is not None:
                return self._trust_result(request_id, normalized, started, pipeline, curated=curated)
            if self.trust is not None and policy_hash is not None:
                try:
                    cached = await asyncio.to_thread(self.trust.lookup, trust_key, policy_hash)
                except sqlite3.Error:
                    cached = None
                if cached is not None:
                    return self._trust_result(request_id, normalized, started, pipeline, cached=cached)

        _progress(on_progress, "crawl", "started")
        crawl_started = time.perf_counter()
        if browser_evidence:
            try:
                evidence = from_browser_payload(normalized, browser_evidence, self.config.min_quality_score)
                supplied_urls = [evidence.final_url, *evidence.redirect_chain]
                for supplied_url in dict.fromkeys(value for value in supplied_urls if value):
                    await asyncio.to_thread(
                        resolve_public_addresses, supplied_url, self.config.allow_private_network
                    )
            except Exception as exc:
                evidence = CrawlEvidence(
                    target_url=normalized,
                    status=CrawlStatus.INVALID_URL,
                    source="browser_client",
                    quality_reasons=["invalid_browser_evidence"],
                    error=f"{type(exc).__name__}: {exc}",
                )
        else:
            evidence = await self.http.fetch(normalized)

        METRICS.crawl_outcomes.labels(
            source=evidence.source, status=evidence.status.value
        ).inc()
        latency = {"browser_input" if browser_evidence else "http": (time.perf_counter() - crawl_started) * 1000}
        # The browser is also the right answer when the plain fetch never got a
        # body. It used to be offered only for PARTIAL and BLOCKED, so a timeout
        # or a reset — the two failures a slow or filtered link actually
        # produces — went straight to crawl_failed with the browser sitting
        # there unused. It carries its own timeouts and a real TLS stack, and
        # frequently succeeds where httpx gave up.
        if (
            not evidence.usable
            and self.browser
            and not browser_evidence
            and not _is_terminal_crawl_failure(evidence)
            and evidence.status in {
                CrawlStatus.PARTIAL,
                CrawlStatus.BLOCKED,
                CrawlStatus.TIMEOUT,
                CrawlStatus.UNREACHABLE,
            }
        ):
            browser_started = time.perf_counter()
            browser_result = await self.browser.fetch(normalized)
            latency["browser"] = (time.perf_counter() - browser_started) * 1000
            if (
                browser_result.usable or _is_terminal_crawl_failure(browser_result)
                or browser_result.quality_score > evidence.quality_score
            ):
                evidence = browser_result
        latency["crawl"] = sum(latency.values())

        if not evidence.usable:
            _progress(on_progress, "crawl", "unavailable")
            result = self._failed_crawl(
                request_id, normalized, evidence, run_fast and pipeline is None, started, latency,
                pipeline=pipeline,
            )
            await self._remember_trust(trust_key, policy_hash, evidence, result, None)
            return result
        _progress(on_progress, "crawl", "completed")
        if pipeline is not None:
            return await self._ordered_pipeline(
                request_id, normalized, evidence, pipeline, started, latency, on_progress,
                decision_thresholds, trust_key, policy_hash,
            )

        if run_fast and self.artifact is not None:
            _progress(on_progress, "rf", "started")
        facts_started = time.perf_counter()
        facts = await collect_domain_facts(evidence.final_url or normalized, self.config.allow_private_network)
        latency["domain_facts"] = (time.perf_counter() - facts_started) * 1000
        features_started = time.perf_counter()
        features = await asyncio.to_thread(extract_features, evidence, facts)
        latency["features"] = (time.perf_counter() - features_started) * 1000
        models_started = time.perf_counter()
        verdict, reasons, scores = self._score_fast(features, evidence, facts, intel_match, run_fast)
        if run_fast:
            latency["fast_models"] = (time.perf_counter() - models_started) * 1000

        # An uncertain HTTP-only result receives one browser-rendered pass so
        # the deterministic model and review service see the same final DOM.
        if verdict == Verdict.SUSPICIOUS and self.browser and evidence.source == "http":
            browser_started = time.perf_counter()
            rendered = await self.browser.fetch(normalized)
            latency["browser"] = (time.perf_counter() - browser_started) * 1000
            latency["crawl"] += latency["browser"]
            if _is_terminal_crawl_failure(rendered):
                result = self._failed_crawl(request_id, normalized, rendered, run_fast, started, latency)
                await self._remember_trust(trust_key, policy_hash, rendered, result, None)
                return result
            if rendered.usable:
                evidence = rendered
                facts_started = time.perf_counter()
                facts = await collect_domain_facts(evidence.final_url or normalized, self.config.allow_private_network)
                latency["domain_facts"] += (time.perf_counter() - facts_started) * 1000
                features_started = time.perf_counter()
                features = await asyncio.to_thread(extract_features, evidence, facts)
                latency["features"] += (time.perf_counter() - features_started) * 1000
                models_started = time.perf_counter()
                verdict, reasons, scores = self._score_fast(
                    features, evidence, facts, intel_match, run_fast
                )
                if run_fast:
                    latency["fast_models"] += (time.perf_counter() - models_started) * 1000
                reasons.append("browser_rendered_recheck")

        fast_verdict = verdict.value if run_fast and self.artifact is not None else None
        if fast_verdict is not None:
            _progress(on_progress, "rf", "completed", verdict)
        combined = scores["combined"]
        enamad_audit: dict[str, Any] | None = None
        if self.config.enamad_verify and evidence.usable:
            seal = extract_seal(evidence.html or "")
            if seal is not None:
                enamad_started = time.perf_counter()
                result_enamad = await verify_seal(
                    seal,
                    evidence.final_url or normalized,
                    self._enamad_http(),
                    timeout_s=self.config.enamad_timeout_s,
                )
                enamad_audit = result_enamad.audit_summary()
                if result_enamad.verified:
                    reasons.append("enamad_seal_verified")
                    # A registry with an authority behind it outranks an
                    # uncertain score, but never a concrete risk signal: a
                    # certified merchant can still be compromised.
                    if (
                        combined is not None and verdict == Verdict.SUSPICIOUS
                        and not _deterministic_risk(features, combined)
                    ):
                        verdict = Verdict.LEGITIMATE
                        reasons.append("enamad_verified_corroboration")
                elif result_enamad.displays_unverified_seal:
                    # Only act on a refusal once the registry is known to be
                    # answering, so an eNamad outage cannot accuse every sealed
                    # site of displaying a stolen badge.
                    if await service_is_answering(self._enamad_http(), timeout_s=self.config.enamad_timeout_s):
                        reasons.append("enamad_seal_not_certified_for_host")
                        enamad_audit["refusal_confirmed"] = True
                latency["enamad"] = (time.perf_counter() - enamad_started) * 1000

        # A requested screener must sign off on a fast clear. Its risk and
        # confidence remain separate from the calibrated scores.
        jev_audit: dict[str, Any] | None = None
        local_jev_audit: dict[str, Any] | None = None
        jev_ms = 0.0
        if run_jev and verdict != Verdict.PHISHING:
            _progress(on_progress, "decision", "started")
        if run_jev and self.jev_local and verdict != Verdict.PHISHING:
            local_started = time.perf_counter()
            try:
                local_risk = await asyncio.to_thread(self.jev_local.score, features)
            except Exception as exc:
                LOGGER.warning("local JEV scoring failed: %s", type(exc).__name__)
                local_risk = None
            verdict, decision = self.jev_local.decide(
                verdict, local_risk, auto_flag=self.config.jev_local_auto_flag
            )
            reasons.append(decision)
            local_jev_audit = {
                "status": "completed" if local_risk is not None else "unavailable",
                "risk": local_risk,
                "decision": decision,
                "review_threshold": self.jev_local.review_threshold,
                "phishing_threshold": self.jev_local.phishing_threshold,
                "latency_ms": round((time.perf_counter() - local_started) * 1000, 3),
            }
        if run_jev and verdict != Verdict.PHISHING and (self.jev is not None or self.jev_local is None):
            jev_started = time.perf_counter()
            if self.jev is None:
                finding = JevFinding(error="jev_not_configured")
            elif (
                self.config.agent_prefetch_references and self.agent and not agent_references
                and verdict == Verdict.SUSPICIOUS
                and (run_fast or not self.config.jev_short_circuit_legit)
            ):
                finding, _ = await asyncio.gather(
                    self._screen(evidence, normalized, features),
                    self.agent.prefetch_references(
                        suspect_url=evidence.final_url or normalized, suspect_html=evidence.html,
                    ),
                )
            else:
                finding = await self._screen(evidence, normalized, features)
            jev_ms = (time.perf_counter() - jev_started) * 1000
            verdict, jev_reasons = apply_jev(
                verdict,
                finding,
                (
                    _observed_risk(features)
                    or features["unicode_confusable_count"] > 0
                    or features["cross_domain_redirect_count"] > 0
                    or "enamad_seal_not_certified_for_host" in reasons
                ),
                self.config,
                standalone=not run_fast and (
                    local_jev_audit is None
                    or local_jev_audit["decision"] == "jev_local_below_review_threshold"
                ),
            )
            reasons.extend(jev_reasons)
            jev_audit = finding.audit_summary()
        decision_audit = jev_audit or local_jev_audit
        if decision_audit is not None:
            _progress(on_progress, "decision", decision_audit["status"], verdict)

        agent_invoked = False
        agent_audit: dict[str, Any] | None = None
        agent_evidence_codes: list[str] = []
        if verdict == Verdict.SUSPICIOUS and self.agent:
            _progress(on_progress, "agent", "started")
            agent_invoked = True
            agent_started = time.perf_counter()
            try:
                agent_review = await self.agent.review(
                    suspect_url=evidence.final_url or normalized,
                    suspect_html=evidence.html,
                    upstream={
                        "request_id": request_id,
                        "rf_score": scores["rf"],
                        "tcn_score": scores["tcn"],
                        "combined_score": combined,
                        "reason_codes": reasons,
                    },
                    references=agent_references or (),
                )
                verdict, agent_reasons = self._reconcile_agent(agent_review, features, combined, evidence)
                reasons.extend(agent_reasons)
                agent_audit = {
                    "status": "unavailable" if agent_review.provider_failed else "completed",
                    **agent_review.audit_summary(),
                }
                if agent_review.provider_error is not None:
                    agent_audit["error_code"] = agent_review.provider_error
                agent_evidence_codes = list(agent_review.evidence_codes)
                METRICS.agent_calls.labels(outcome=agent_audit["status"]).inc()
                METRICS.agent_reconciliation.labels(
                    agent_verdict=str(agent_review.verdict_candidate),
                    final_verdict=verdict.value,
                    corroborated=str(verdict != Verdict.SUSPICIOUS).lower(),
                ).inc()
            except AgentServiceError as exc:
                reasons.extend(["agent_unavailable", exc.code])
                agent_audit = {"status": "failed", "error_code": exc.code}
                METRICS.agent_calls.labels(outcome=f"failed_{exc.code}"[:64]).inc()
                verdict = Verdict.SUSPICIOUS
            except Exception as exc:
                reasons.extend(["agent_unavailable", type(exc).__name__.lower()])
                agent_audit = {
                    "status": "failed",
                    "error_code": f"client_{type(exc).__name__.lower()}",
                }
                METRICS.agent_calls.labels(
                    outcome=f"failed_client_{type(exc).__name__.lower()}"[:64]
                ).inc()
                verdict = Verdict.SUSPICIOUS
            agent_ms = (time.perf_counter() - agent_started) * 1000
            METRICS.agent_duration.observe(agent_ms / 1000.0)
            _progress(on_progress, "agent", "completed" if agent_audit["status"] == "completed" else "unavailable", verdict)
        else:
            agent_ms = 0.0

        evidence_summary = evidence.public_dict()
        if fast_verdict is not None:
            evidence_summary["fast_verdict"] = fast_verdict
        if enamad_audit is not None:
            evidence_summary["enamad"] = enamad_audit
        if jev_audit is not None:
            evidence_summary["jev"] = jev_audit
        if local_jev_audit is not None:
            evidence_summary["jev_local"] = local_jev_audit
        if agent_audit is not None:
            evidence_summary["agent_review"] = agent_audit
        stage = "browser" if evidence.source.startswith("browser") else "fast"
        risk_score = combined if combined is not None else 0.5
        if agent_invoked:
            stage = "agent"
        elif local_jev_audit and local_jev_audit["decision"] == "jev_local_phishing_threshold":
            stage = "jev_local"
            risk_score = local_jev_audit["risk"]

        result = self._result(
            request_id, normalized, evidence.final_url or normalized, verdict,
            risk_score,
            stage,
            evidence.status, reasons, scores, started, evidence_summary,
            extra_latency={**latency, "agent": agent_ms, "jev": jev_ms},
            evidence_items=derive_evidence(
                features,
                intel_match=intel_match,
                crawl_status=evidence.status.value,
                agent_codes=agent_evidence_codes,
            ),
        )
        if result.verdict in {Verdict.SUSPICIOUS, Verdict.CRAWL_FAILED}:
            self._enqueue(result)
        await self._remember_trust(trust_key, policy_hash, evidence, result, features)
        self._persist(result)
        return result

    async def _ordered_pipeline(
        self, request_id: str, url: str, evidence: CrawlEvidence,
        pipeline: Sequence[PipelineStage], started: float, latency: dict[str, float],
        on_progress: ProgressCallback | None = None,
        decision_thresholds: DecisionThresholds | None = None,
        trust_key: str | None = None,
        policy_hash: str | None = None,
    ) -> DetectionResult:
        final_url = evidence.final_url or url
        verdict = Verdict.SUSPICIOUS
        reasons: list[str] = []
        features: Mapping[str, float] | None = None
        scores: dict[str, float | None] = dict.fromkeys(("rf", "tcn", "combined", "ood_fraction"))
        risk = 0.5
        decisive_stage = "pipeline"
        steps: list[dict[str, Any]] = []
        summary = evidence.public_dict()
        summary["pipeline"] = steps
        references: list[dict[str, Any]] = []
        agent_codes: list[str] = []
        decision_blocks_clear = False

        for stage in pipeline:
            if verdict != Verdict.SUSPICIOUS:
                steps.append({"stage": stage, "status": "skipped"})
                continue
            step: dict[str, Any] = {"stage": stage, "status": "completed"}
            steps.append(step)
            _progress(on_progress, stage, "started")
            stage_started = time.perf_counter()
            try:
                if stage == "rf":
                    if not self.config.fast_models_enabled or self.artifact is None:
                        raise AgentServiceError("fast_models_unavailable")
                    facts = await collect_domain_facts(final_url, self.config.allow_private_network)
                    features = await asyncio.to_thread(extract_features, evidence, facts)
                    verdict, rf_reasons, scores = self._score_fast(features, evidence, facts, None, True)
                    summary["fast_verdict"] = verdict.value
                    reasons.extend(rf_reasons)
                    if verdict == Verdict.LEGITIMATE and decision_blocks_clear:
                        verdict = Verdict.SUSPICIOUS
                        reasons.append("decision_model_requires_review")
                    risk = scores["combined"] if scores["combined"] is not None else risk
                elif stage == "decision":
                    if features is None:
                        features = await asyncio.to_thread(extract_features, evidence, DomainFacts())
                    verdict, opinion, decision_reasons = await self._pipeline_decision(
                        evidence, url, features, decision_thresholds,
                    )
                    summary["jev" if self.jev is not None else "jev_local"] = opinion
                    reasons.extend(decision_reasons)
                    decision_blocks_clear = (
                        opinion["status"] != "completed"
                        or "jev_escalated_to_review" in decision_reasons
                        or "jev_local_review_threshold" in decision_reasons
                    )
                    if opinion["risk"] is not None:
                        risk = opinion["risk"]
                    step["status"] = opinion["status"]
                elif stage == "rag":
                    if self.agent is None:
                        raise AgentServiceError("reference_service_unconfigured")
                    references, matches = await self.agent.retrieve_references(
                        suspect_url=final_url, suspect_html=evidence.html,
                    )
                    summary["rag"] = {"references_retrieved": len(references), "reference_matches": matches}
                    reasons.append("rag_search_completed")
                    reasons.append("rag_references_retrieved" if references else "rag_no_references")
                elif stage == "agent":
                    if self.agent is None:
                        raise AgentServiceError("agent_service_not_configured")
                    if features is None:
                        features = await asyncio.to_thread(extract_features, evidence, DomainFacts())
                    review = await self.agent.review(
                        suspect_url=final_url, suspect_html=evidence.html,
                        upstream={
                            "request_id": request_id, "rf_score": scores["rf"], "tcn_score": scores["tcn"],
                            "combined_score": scores["combined"], "reason_codes": reasons,
                        },
                        references=references, automatic_references=False,
                    )
                    verdict, agent_reasons = self._reconcile_agent(review, features, scores["combined"], evidence)
                    reasons.extend(agent_reasons)
                    step["status"] = "unavailable" if review.provider_failed else "completed"
                    summary["agent_review"] = {"status": step["status"], **review.audit_summary()}
                    if review.provider_error is not None:
                        step["error_code"] = review.provider_error
                        summary["agent_review"]["error_code"] = review.provider_error
                    agent_codes = list(review.evidence_codes)
                    risk = review.risk_score if review.risk_score is not None else risk
            except Exception as exc:
                code = exc.code if isinstance(exc, AgentServiceError) else type(exc).__name__.lower()
                LOGGER.warning("%s pipeline stage failed: %s", stage, code)
                step.update(status="unavailable", error_code=code)
                reasons.append(f"{stage}_unavailable")
                if stage == "decision":
                    decision_blocks_clear = True
            duration = (time.perf_counter() - stage_started) * 1000
            latency[stage] = duration
            step.update(verdict=verdict.value, latency_ms=round(duration, 3))
            _progress(on_progress, stage, step["status"], verdict)
            if verdict != Verdict.SUSPICIOUS:
                decisive_stage = stage

        result = self._result(
            request_id, url, final_url, verdict, risk, decisive_stage, evidence.status, reasons,
            scores, started, summary, extra_latency=latency,
            evidence_items=derive_evidence(features, crawl_status=evidence.status.value, agent_codes=agent_codes),
        )
        if verdict == Verdict.SUSPICIOUS:
            self._enqueue(result)
        await self._remember_trust(trust_key, policy_hash, evidence, result, features)
        self._persist(result)
        return result

    async def _pipeline_decision(
        self, evidence: CrawlEvidence, url: str, features: Mapping[str, float],
        thresholds: DecisionThresholds | None = None,
    ) -> tuple[Verdict, dict[str, Any], list[str]]:
        if self.jev is not None:
            finding = await self._screen(evidence, url, features)
            policy = thresholds or DecisionThresholds.from_config(self.config, ordered_pipeline=True)
            verdict, reasons = apply_jev(
                Verdict.SUSPICIOUS, finding,
                _observed_risk(features) or features["unicode_confusable_count"] > 0
                or features["cross_domain_redirect_count"] > 0,
                self.config, standalone=True, thresholds=policy,
            )
            return verdict, {
                **finding.audit_summary(),
                "thresholds": policy.model_dump(),
                "gates": [reason for reason in reasons if reason.startswith("jev_gate_")],
            }, reasons
        if self.jev_local is None:
            raise AgentServiceError("decision_model_unconfigured")
        risk = await asyncio.to_thread(self.jev_local.score, features)
        verdict, reason = self.jev_local.decide(
            Verdict.SUSPICIOUS, risk, auto_flag=self.config.jev_local_auto_flag,
        )
        return verdict, {"status": "completed", "risk": risk, "decision": reason}, [reason]

    async def _screen(
        self, evidence: CrawlEvidence, normalized: str, features: Mapping[str, float],
    ) -> JevFinding:
        assert self.jev is not None
        visible = await asyncio.to_thread(screening_text, evidence.html, self.config.jev_max_text_chars)
        if not visible:
            return JevFinding(error="jev_empty_visible_text")
        url = evidence.final_url or normalized
        return await self.jev.score(url=url, visible_text=visible, structure=jev_structure(features, url))

    def _failed_crawl(
        self, request_id: str, normalized: str, evidence: CrawlEvidence, run_fast: bool,
        started: float, latency: Mapping[str, float],
        *, pipeline: Sequence[PipelineStage] | None = None,
    ) -> DetectionResult:
        summary = evidence.public_dict()
        if pipeline is not None:
            summary["pipeline"] = [{"stage": stage, "status": "skipped"} for stage in pipeline]
        result = self._result(
            request_id, normalized, evidence.final_url or normalized, Verdict.CRAWL_FAILED, 0.5,
            "browser" if evidence.source.startswith("browser") else "http",
            evidence.status, ["crawl_not_usable", *evidence.quality_reasons],
            {"rf": None, "tcn": self._predict_tcn(normalized) if run_fast and not _is_terminal_crawl_failure(evidence) else None},
            started, summary, extra_latency=latency,
            evidence_items=derive_evidence(crawl_status=evidence.status.value),
        )
        self._enqueue(result)
        self._persist(result)
        return result

    def _score_fast(
        self,
        features: Mapping[str, float],
        evidence: CrawlEvidence,
        facts: DomainFacts,
        intel_match: IntelMatch | None,
        enabled: bool,
    ) -> tuple[Verdict, list[str], dict[str, float | None]]:
        if not enabled or self.artifact is None:
            reason = "model_artifact_missing" if enabled else "fast_models_skipped"
            return Verdict.SUSPICIOUS, [reason], dict.fromkeys(("rf", "tcn", "combined", "ood_fraction"))

        rf_features, scored_origin = _rf_input_features(
            features, evidence, facts, self.config.score_origin
        )
        rf, ood = self.artifact.predict_rf(rf_features)
        tcn = self._predict_tcn(evidence.final_url or evidence.target_url)
        combined = self.artifact.combine_scores(rf, tcn)
        verdict = self.artifact.policy.decide(combined, ood)
        reasons = ["calibrated_fast_policy"]
        if not self.artifact.policy.production_ready:
            reasons.append("bootstrap_policy_not_production_validated")
            if verdict == Verdict.PHISHING:
                if self._bootstrap_phishing_supported(features, rf, tcn):
                    reasons.append("bootstrap_cross_evidence_supported")
                else:
                    verdict = Verdict.SUSPICIOUS
                    reasons.append("bootstrap_phishing_requires_corroboration")
        if scored_origin:
            reasons.append("rf_scored_on_origin")
        if intel_match and self._can_corroborate_benign(intel_match, features, combined, ood):
            verdict = Verdict.LEGITIMATE
            reasons.extend(["verified_benign_history_corroboration", f"intel_{intel_match.source}"])
        return verdict, reasons, {"rf": rf, "tcn": tcn, "combined": combined, "ood_fraction": ood}

    def _predict_tcn(self, url: str) -> Optional[float]:
        if not self.tcn:
            return None
        try:
            return self.tcn.predict(url)
        except Exception:
            return None

    def _can_corroborate_benign(
        self,
        match: Optional[IntelMatch],
        features: Mapping[str, float],
        score: float,
        ood_fraction: float,
    ) -> bool:
        if not match or match.verdict != "benign" or not self.artifact:
            return False
        if score >= 0.10 or ood_fraction > self.artifact.policy.max_ood_fraction:
            return False
        return (
            features["external_form_action_count"] == 0
            and features["suspicious_token_count"] < 2
            and features["path_depth"] <= 4
            and features["cross_domain_redirect_count"] == 0
            and features["unicode_confusable_count"] == 0
        )

    def _bootstrap_phishing_supported(
        self,
        features: Mapping[str, float],
        rf_probability: Optional[float],
        tcn_probability: Optional[float],
    ) -> bool:
        if not self.artifact:
            return False
        threshold = self.artifact.policy.phishing_threshold
        cross_model_agreement = (
            rf_probability is not None
            and tcn_probability is not None
            and rf_probability >= threshold
            and tcn_probability >= threshold
        )
        deterministic_mismatch = (
            features["external_form_action_count"] > 0
            or features["cross_domain_redirect_count"] > 0
            or features["unicode_confusable_count"] > 0
            or (
                features["password_input_count"] > 0
                and features["title_domain_token_overlap"] == 0
            )
        )
        return cross_model_agreement or deterministic_mismatch
    @staticmethod
    def _reconcile_agent(
        review: AgentReview,
        features: Mapping[str, float],
        combined_score: float | None,
        evidence: CrawlEvidence,
    ) -> Tuple[Verdict, list[str]]:
        if review.provider_failed:
            return Verdict.SUSPICIOUS, [
                "agent_review_unavailable", *review.reasons, *review.evidence_codes, "agent_advisory_abstained",
            ]
        reasons = ["agent_review_completed", *review.reasons, *review.evidence_codes]
        deterministic_risk = _deterministic_risk(features, combined_score)
        # The reviewer's own concrete-support finding counts as corroboration.
        #
        # _deterministic_risk is a heuristic over the detector's URL and DOM
        # features, and it cannot see what the reviewer established: that the
        # page titles itself as a brand whose real domain is something else, or
        # that a link destination is a homograph. Requiring the detector to
        # independently rediscover risk it has no features for meant the
        # reviewer could conclude phishing with concrete evidence and be
        # overruled by a weaker check — measured on nine live impersonation
        # pages, every one of which the reviewer resolved as
        # two_pass_phishing_with_concrete_support and the detector reported as
        # suspicious.
        #
        # That reason code is the reviewer asserting it holds deterministic
        # evidence, not a model opinion; it is only ever set after both passes
        # agree and a concrete signal is present.
        reviewer_established_support = "two_pass_phishing_with_concrete_support" in review.reasons
        if (
            review.verdict_candidate == "phishing"
            and review.risk_score is not None
            and review.risk_score >= 0.80
            and review.confidence >= 0.75
            and (deterministic_risk or reviewer_established_support)
        ):
            return Verdict.PHISHING, reasons + ["agent_advisory_phishing_corroborated"]
        # Cleared against what was observed, not against the ensemble's opinion.
        # A high combined score is the models finding the page unusual, and a
        # large modern site is unusual: hidden forms, obfuscated bundles and
        # shadow roots are its ordinary furniture. Letting that veto a clearance
        # meant the agent could never rescue exactly the sites it was best
        # placed to recognise.
        if (
            review.verdict_candidate == "legitimate"
            and review.risk_score is not None
            and review.risk_score <= 0.20
            and review.confidence >= 0.75
            and not _observed_risk(features)
            and evidence.usable
        ):
            return Verdict.LEGITIMATE, reasons + ["agent_advisory_legitimate_corroborated"]
        if review.verdict_candidate == "crawl_failed":
            return Verdict.SUSPICIOUS, reasons + ["agent_input_quality_disagreement"]
        return Verdict.SUSPICIOUS, reasons + ["agent_advisory_abstained"]

    def _result(
        self,
        request_id: str,
        url: str,
        final_url: str,
        verdict: Verdict,
        score: float,
        stage: str,
        crawl_status: CrawlStatus,
        reasons: list[str],
        scores: Mapping[str, Optional[float]],
        started: float,
        evidence: Mapping[str, Any],
        extra_latency: Mapping[str, float] | None = None,
        evidence_items: list[dict[str, str]] | None = None,
    ) -> DetectionResult:
        latency = dict(extra_latency or {})
        latency["total"] = (time.perf_counter() - started) * 1000
        result = DetectionResult(
            request_id=request_id,
            url=url,
            final_url=final_url,
            verdict=verdict,
            risk_score=round(float(score), 6),
            stage=stage,
            crawl_status=crawl_status,
            reason_codes=list(dict.fromkeys(reasons)),
            model_scores={key: None if value is None else round(float(value), 6) for key, value in scores.items()},
            model_version=self.artifact.model_version if self.artifact else "v2-no-artifact",
            latency_ms={key: round(float(value), 3) for key, value in latency.items()},
            evidence=list(evidence_items or []),
            evidence_summary=dict(evidence),
        )
        record_detection(result)
        return result

    def _enqueue(self, result: DetectionResult) -> None:
        self.review.enqueue(
            request_id=result.request_id,
            url=result.url,
            verdict=result.verdict.value,
            risk_score=result.risk_score,
            reason_codes=result.reason_codes,
            evidence=result.evidence_summary,
        )
        try:
            METRICS.review_queue_depth.set(len(self.review.pending(500)))
        except Exception:
            # Queue depth is a convenience gauge; never fail a detection for it.
            pass

    def _persist(self, result: DetectionResult) -> None:
        self.config.result_dir.mkdir(parents=True, exist_ok=True)
        path = self.config.result_dir / f"{result.request_id}.json"
        path.write_text(json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8")
