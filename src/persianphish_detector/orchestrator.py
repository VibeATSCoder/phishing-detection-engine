from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Mapping, Optional, Sequence, Tuple

from .agent import AgentClient, AgentReview, AgentServiceError
from .config import DetectorConfig
from .crawl import BrowserCrawler, HttpCrawler, from_browser_payload
from .domain_facts import collect_domain_facts
from .features import extract_features
from .intel import IntelMatch, IntelStore
from .observability import METRICS, record_detection, span, url_labels
from .models import DetectorArtifact, load_artifact
from .models.tcn import ONNXTCNPredictor, TCN_INPUT_CONTRACT
from .review import ReviewStore
from .types import CrawlEvidence, CrawlStatus, DetectionResult, Verdict
from .url_utils import UnsafeURL, canonical_url, resolve_public_addresses


class Detector:
    def __init__(self, config: DetectorConfig) -> None:
        self.config = config
        self.http = HttpCrawler(
            timeout_s=config.http_timeout_s,
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
        self.artifact: Optional[DetectorArtifact] = load_artifact(config.artifact_path) if config.artifact_path.exists() else None
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

    async def close(self) -> None:
        if self.browser:
            await self.browser.close()
        if self.agent:
            await self.agent.close()

    async def detect(
        self,
        url: str,
        browser_evidence: Mapping[str, Any] | None = None,
        agent_references: Sequence[Mapping[str, Any]] | None = None,
    ) -> DetectionResult:
        """Trace-wrapped entry point; the pipeline itself lives in ``_detect``."""
        with span("detector.detect", **url_labels(url)):
            return await self._detect(url, browser_evidence, agent_references)

    async def _detect(
        self,
        url: str,
        browser_evidence: Mapping[str, Any] | None = None,
        agent_references: Sequence[Mapping[str, Any]] | None = None,
    ) -> DetectionResult:
        started = time.perf_counter()
        request_id = uuid.uuid4().hex
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
        if intel_match:
            METRICS.intel_matches.labels(
                source=intel_match.source, verdict=intel_match.verdict
            ).inc()
        if intel_match and intel_match.verdict == "phishing":
            return self._result(
                request_id, normalized, normalized, Verdict.PHISHING, 1.0, "reputation",
                CrawlStatus.PARTIAL, ["exact_local_phishing_feed_match", f"intel_{intel_match.source}"],
                {"rf": None, "tcn": None}, started, {"intel": asdict(intel_match)},
            )

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
        crawl_ms = evidence.elapsed_ms
        if not evidence.usable and self.browser and not browser_evidence and evidence.status in {CrawlStatus.PARTIAL, CrawlStatus.BLOCKED}:
            browser_result = await self.browser.fetch(normalized)
            if browser_result.usable or browser_result.quality_score > evidence.quality_score:
                evidence = browser_result
                crawl_ms += browser_result.elapsed_ms

        if not evidence.usable:
            result = self._result(
                request_id, normalized, evidence.final_url or normalized, Verdict.CRAWL_FAILED, 0.5,
                "browser" if evidence.source.startswith("browser") else "http",
                evidence.status, ["crawl_not_usable", *evidence.quality_reasons],
                {"rf": None, "tcn": self._predict_tcn(normalized)}, started,
                evidence.public_dict(), extra_latency={"crawl": crawl_ms},
            )
            self._enqueue(result)
            self._persist(result)
            return result

        facts_started = time.perf_counter()
        facts = await collect_domain_facts(evidence.final_url or normalized, self.config.allow_private_network)
        facts_ms = (time.perf_counter() - facts_started) * 1000
        features = extract_features(evidence, facts)
        rf_probability: Optional[float] = None
        ood_fraction = 1.0
        if self.artifact:
            rf_probability, ood_fraction = self.artifact.predict_rf(features)
        tcn_probability = self._predict_tcn(evidence.final_url or normalized)
        combined = self._combine_scores(rf_probability, tcn_probability)
        scores = {"rf": rf_probability, "tcn": tcn_probability, "combined": combined, "ood_fraction": ood_fraction}

        if not self.artifact:
            verdict = Verdict.SUSPICIOUS
            reasons = ["model_artifact_missing"]
        else:
            verdict = self.artifact.policy.decide(combined, ood_fraction)
            reasons = ["calibrated_fast_policy"]
            if not self.artifact.policy.production_ready:
                reasons.append("bootstrap_policy_not_production_validated")
                if verdict == Verdict.PHISHING:
                    if self._bootstrap_phishing_supported(features, rf_probability, tcn_probability):
                        reasons.append("bootstrap_cross_evidence_supported")
                    else:
                        verdict = Verdict.SUSPICIOUS
                        reasons.append("bootstrap_phishing_requires_corroboration")

        if self._can_corroborate_benign(intel_match, features, combined, ood_fraction):
            verdict = Verdict.LEGITIMATE
            reasons.extend(["verified_benign_history_corroboration", f"intel_{intel_match.source}"])

        # An uncertain HTTP-only result receives one browser-rendered pass so
        # the deterministic model and review service see the same final DOM.
        if verdict == Verdict.SUSPICIOUS and self.browser and evidence.source == "http":
            rendered = await self.browser.fetch(normalized)
            crawl_ms += rendered.elapsed_ms
            if rendered.usable:
                evidence = rendered
                facts_started = time.perf_counter()
                facts = await collect_domain_facts(evidence.final_url or normalized, self.config.allow_private_network)
                facts_ms += (time.perf_counter() - facts_started) * 1000
                features = extract_features(evidence, facts)
                if self.artifact:
                    rf_probability, ood_fraction = self.artifact.predict_rf(features)
                tcn_probability = self._predict_tcn(evidence.final_url or normalized)
                combined = self._combine_scores(rf_probability, tcn_probability)
                scores = {"rf": rf_probability, "tcn": tcn_probability, "combined": combined, "ood_fraction": ood_fraction}
                if self.artifact:
                    verdict = self.artifact.policy.decide(combined, ood_fraction)
                    if (
                        verdict == Verdict.PHISHING
                        and not self.artifact.policy.production_ready
                        and not self._bootstrap_phishing_supported(features, rf_probability, tcn_probability)
                    ):
                        verdict = Verdict.SUSPICIOUS
                        reasons.append("bootstrap_phishing_requires_corroboration")
                reasons.append("browser_rendered_recheck")
                if self._can_corroborate_benign(intel_match, features, combined, ood_fraction):
                    verdict = Verdict.LEGITIMATE
                    reasons.append("verified_benign_history_corroboration")

        agent_invoked = False
        agent_audit: dict[str, Any] | None = None
        if verdict == Verdict.SUSPICIOUS and self.agent:
            agent_invoked = True
            agent_started = time.perf_counter()
            try:
                agent_review = await self.agent.review(
                    suspect_url=evidence.final_url or normalized,
                    suspect_html=evidence.html,
                    upstream={
                        "request_id": request_id,
                        "rf_score": rf_probability,
                        "tcn_score": tcn_probability,
                        "combined_score": combined,
                        "reason_codes": reasons,
                    },
                    references=agent_references or (),
                )
                verdict, agent_reasons = self._reconcile_agent(agent_review, features, combined, evidence)
                reasons.extend(agent_reasons)
                agent_audit = {"status": "completed", **agent_review.audit_summary()}
                METRICS.agent_calls.labels(outcome="completed").inc()
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
        else:
            agent_ms = 0.0

        evidence_summary = evidence.public_dict()
        if agent_audit is not None:
            evidence_summary["agent_review"] = agent_audit
        result = self._result(
            request_id, normalized, evidence.final_url or normalized, verdict, combined,
            "agent" if agent_invoked else ("browser" if evidence.source.startswith("browser") else "fast"),
            evidence.status, reasons, scores, started, evidence_summary,
            extra_latency={"crawl": crawl_ms, "domain_facts": facts_ms, "agent": agent_ms},
        )
        if result.verdict in {Verdict.SUSPICIOUS, Verdict.CRAWL_FAILED}:
            self._enqueue(result)
        self._persist(result)
        return result

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
    def _combine_scores(self, rf: Optional[float], tcn: Optional[float]) -> float:
        # Kept as a compatibility fallback for artifacts without an ensemble
        # contract. Detector.detect uses the artifact combiner when available.
        if self.artifact:
            return self.artifact.combine_scores(rf, tcn)
        if rf is None and tcn is None:
            return 0.5
        return float(tcn if rf is None else rf)

    @staticmethod
    def _reconcile_agent(
        review: AgentReview,
        features: Mapping[str, float],
        combined_score: float,
        evidence: CrawlEvidence,
    ) -> Tuple[Verdict, list[str]]:
        reasons = ["agent_review_completed", *review.reasons, *review.evidence_codes]
        deterministic_risk = (
            combined_score >= 0.5
            or features["external_form_action_count"] > 0
            or features["suspicious_token_count"] >= 2
            or (features["password_input_count"] > 0 and features["title_domain_token_overlap"] == 0)
        )
        if (
            review.verdict_candidate == "phishing"
            and review.risk_score is not None
            and review.risk_score >= 0.80
            and review.confidence >= 0.75
            and deterministic_risk
        ):
            return Verdict.PHISHING, reasons + ["agent_advisory_phishing_corroborated"]
        if (
            review.verdict_candidate == "legitimate"
            and review.risk_score is not None
            and review.risk_score <= 0.20
            and review.confidence >= 0.75
            and not deterministic_risk
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
