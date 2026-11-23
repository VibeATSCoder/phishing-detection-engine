from __future__ import annotations

import asyncio
import json
import logging
import hmac
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, StreamingResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import __version__
from .body_limit import RequestBodyLimitMiddleware
from .config import DetectorConfig
from .observability import (
    configure_tracing,
    instrument_app,
    set_build_info,
)
from .jev import DecisionThresholds
from .orchestrator import Detector, PIPELINE_STAGES, PipelineStage
from .url_utils import canonical_url


LOGGER = logging.getLogger(__name__)
DETECT_STREAM = "application/x-ndjson"
MAX_REQUEST_BODY_BYTES = 14_000_000

# Declared purely so the OpenAPI schema advertises the key and the Swagger
# UI shows an "Authorize" button that sends X-API-Key on "Try it out".
# auto_error=False means it never rejects on its own: the optional_api_key
# middleware below is the one place the key is actually checked, so open
# paths stay open and behaviour is identical whether or not a key is set.
api_key_scheme = APIKeyHeader(name="X-API-Key", auto_error=False)


class BrowserEvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    final_url: str
    http_status: int = Field(default=200, ge=100, le=599)
    content_type: str = "text/html"
    dom_html: str = Field(max_length=5_000_000)
    screenshot_base64: Optional[str] = Field(default=None, max_length=2_800_000)
    redirect_chain: List[str] = Field(default_factory=list, max_length=20)
    network_hosts: List[str] = Field(default_factory=list, max_length=500)


class AgentReferenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reference_id: str = Field(min_length=1, max_length=128)
    official_url: str = Field(min_length=1, max_length=8192)
    html: str
    retrieval_score: float = Field(ge=0, le=1)
    brand_name: Optional[str] = Field(default=None, max_length=200)
    retrieved_at: Optional[datetime] = None
    content_sha256: Optional[str] = Field(default=None, pattern=r"^[a-fA-F0-9]{64}$")

    @field_validator("official_url")
    @classmethod
    def validate_official_url(cls, value: str) -> str:
        return canonical_url(value)

    @field_validator("html")
    @classmethod
    def validate_html_size(cls, value: str) -> str:
        if len(value.encode("utf-8", errors="replace")) > 2_000_000:
            raise ValueError("agent_reference_html_too_large")
        return value

    @model_validator(mode="after")
    def validate_content_hash(self) -> "AgentReferenceRequest":
        if self.content_sha256:
            digest = hashlib.sha256(self.html.encode("utf-8", errors="replace")).hexdigest()
            if digest.lower() != self.content_sha256.lower():
                raise ValueError("agent_reference_content_hash_mismatch")
        return self


class DetectRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str = Field(min_length=1, max_length=8192)
    browser_evidence: Optional[BrowserEvidenceRequest] = None
    agent_references: List[AgentReferenceRequest] = Field(default_factory=list, max_length=3)
    #: Per-request override for the optional JEV screener. null = follow the
    #: service config; false = skip it; true = request screening.
    use_jev: Optional[bool] = None
    #: False skips the RF/TCN ensemble. True uses it when enabled by the service.
    use_rf: Optional[bool] = None
    pipeline: list[PipelineStage] | None = Field(default=None, min_length=1, max_length=4)
    decision_thresholds: DecisionThresholds | None = None
    use_trusted_urls: bool = Field(default=True, description="Reuse a trusted result before crawling.")

    @model_validator(mode="after")
    def validate_total_reference_size(self) -> "DetectRequest":
        if self.pipeline is not None:
            if len(self.pipeline) != len(set(self.pipeline)):
                raise ValueError("duplicate_pipeline_stage")
            if self.use_rf is not None or self.use_jev is not None or self.agent_references:
                raise ValueError("pipeline_conflicts_with_legacy_stage_controls")
        if self.decision_thresholds is not None and "decision" not in (self.pipeline or ()):
            raise ValueError("decision_thresholds_require_decision_stage")
        total = sum(len(item.html.encode("utf-8", errors="replace")) for item in self.agent_references)
        if total > 5_000_000:
            raise ValueError("agent_reference_total_too_large")
        identifiers = [item.reference_id for item in self.agent_references]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("duplicate_agent_reference_id")
        return self


class ReviewResolution(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str
    note: str = Field(default="", max_length=2000)

    @field_validator("label")
    @classmethod
    def validate_label(cls, value: str) -> str:
        if value not in {"legitimate", "phishing", "crawl_failed", "discard"}:
            raise ValueError("invalid review label")
        return value


def create_app(config: DetectorConfig | None = None) -> FastAPI:
    selected_config = config or DetectorConfig.from_env()

    configure_tracing(service_version=__version__)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        detector = Detector(selected_config)
        app.state.detector = detector
        artifact = detector.artifact
        set_build_info(
            __version__,
            artifact.model_version if artifact else "no-artifact",
            artifact.policy.production_ready if artifact else False,
        )
        yield
        await app.state.detector.close()

    app = FastAPI(
        title="PersianPhish Real-World Detector",
        version=__version__,
        description="Four-state phishing detection with crawl-quality gating and bounded agentic review.",
        lifespan=lifespan,
    )
    app.add_middleware(RequestBodyLimitMiddleware, max_bytes=MAX_REQUEST_BODY_BYTES)
    instrument_app(app)

    @app.middleware("http")
    async def optional_api_key(request: Request, call_next):
        # The liveness/readiness/metrics probes and the API documentation are
        # exempt from the key. The OpenAPI schema describes the shape of the API,
        # not its data, so serving it is not a disclosure — and a detector put on
        # a public address with a key set would otherwise 401 its own Swagger UI,
        # defeating the reason the docs exist. Every endpoint that acts on a URL
        # still requires the key.
        _open_paths = {"/health", "/ready", "/metrics", "/docs", "/redoc", "/openapi.json"}
        if selected_config.api_key and request.url.path not in _open_paths:
            supplied = request.headers.get("x-api-key", "")
            if not hmac.compare_digest(supplied, selected_config.api_key):
                from fastapi.responses import JSONResponse

                return JSONResponse(status_code=401, content={"detail": "invalid API key"})
        return await call_next(request)

    @app.get("/health")
    async def health(request: Request) -> Dict[str, Any]:
        detector: Detector = request.app.state.detector
        return {
            "status": "ok",
            "service_version": __version__,
            "model_loaded": detector.artifact is not None,
            "model_version": detector.artifact.model_version if detector.artifact else None,
            "tcn_loaded": detector.tcn is not None,
            "fast_models_enabled": selected_config.fast_models_enabled,
            "jev_configured": detector.jev is not None or detector.jev_local is not None,
            "jev_local_configured": detector.jev_local is not None,
            "jev_default_enabled": selected_config.jev_enabled,
            "policy_production_ready": detector.artifact.policy.production_ready if detector.artifact else False,
            "agent_configured": detector.agent is not None,
            "browser_enabled": detector.browser is not None,
            "trusted_urls_enabled": selected_config.trusted_urls_enabled,
        }

    @app.get("/ready")
    async def ready(request: Request) -> JSONResponse:
        detector: Detector = request.app.state.detector
        model_ready = detector.artifact is not None
        tcn_ready = detector.tcn is not None
        fast_ready = (model_ready and tcn_ready) or not selected_config.fast_models_enabled
        agent_ready = (
            await detector.agent.ready() if detector.agent else selected_config.fast_models_enabled
        )
        ready_state = fast_ready and agent_ready
        return JSONResponse(
            status_code=200 if ready_state else 503,
            content={
                "ready": ready_state,
                "service_version": __version__,
                "model_loaded": model_ready,
                "tcn_loaded": tcn_ready,
                "fast_models_enabled": selected_config.fast_models_enabled,
                "jev_configured": detector.jev is not None or detector.jev_local is not None,
                "jev_local_configured": detector.jev_local is not None,
                "jev_default_enabled": selected_config.jev_enabled,
                "agent_configured": detector.agent is not None,
                "agent_ready": agent_ready,
            },
        )

    @app.get("/v1/pipeline", dependencies=[Depends(api_key_scheme)])
    async def pipeline_capabilities(request: Request) -> dict[str, Any]:
        detector: Detector = request.app.state.detector
        return {
            "service_version": __version__,
            "stages": list(PIPELINE_STAGES),
            "decision_thresholds": detector.jev is not None,
            "trusted_urls": selected_config.trusted_urls_enabled,
            "configured": {
                "rf": selected_config.fast_models_enabled and detector.artifact is not None,
                "decision": detector.jev is not None or detector.jev_local is not None,
                "rag": detector.agent is not None,
                "agent": detector.agent is not None,
            },
        }

    @app.post(
        "/v1/detect", dependencies=[Depends(api_key_scheme)], response_model=dict[str, Any],
        responses={200: {"content": {DETECT_STREAM: {}}}},
    )
    async def detect(payload: DetectRequest, request: Request) -> Dict[str, Any] | StreamingResponse:
        detector: Detector = request.app.state.detector
        browser_payload = payload.browser_evidence.model_dump() if payload.browser_evidence else None
        agent_references = [item.model_dump(mode="json") for item in payload.agent_references]
        options: dict[str, Any] = {"use_jev": payload.use_jev, "use_rf": payload.use_rf}
        if not payload.use_trusted_urls:
            options["use_trusted_urls"] = False
        if payload.pipeline is not None:
            options["pipeline"] = payload.pipeline
        if payload.decision_thresholds is not None:
            if detector.jev is None:
                raise HTTPException(status_code=422, detail="decision_thresholds_require_remote_provider")
            options["decision_thresholds"] = payload.decision_thresholds

        async def run(**extra: Any) -> dict[str, Any]:
            result = await detector.detect(payload.url, browser_payload, agent_references, **options, **extra)
            return result.to_dict()

        accepted_types = {part.split(";", 1)[0].strip().lower() for part in request.headers.get("accept", "").split(",")}
        if DETECT_STREAM not in accepted_types:
            return await run()

        async def stream():
            events: asyncio.Queue[dict[str, Any]] = asyncio.Queue()

            async def detect_and_publish() -> None:
                try:
                    result = await run(on_progress=events.put_nowait)
                    events.put_nowait({"type": "result", "result": result})
                except Exception as exc:
                    LOGGER.error("streamed detection failed: %s", type(exc).__name__)
                    events.put_nowait({"type": "error"})

            task = asyncio.create_task(detect_and_publish())
            try:
                while True:
                    try:
                        event = await asyncio.wait_for(events.get(), timeout=10)
                    except TimeoutError:
                        event = {"type": "heartbeat"}
                    yield json.dumps(event, separators=(",", ":")) + "\n"
                    if event["type"] in {"result", "error"}:
                        return
            finally:
                task.cancel()
                await asyncio.gather(task, return_exceptions=True)

        return StreamingResponse(
            stream(), media_type=DETECT_STREAM,
            headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"},
        )

    @app.get("/v1/detect/{request_id}", dependencies=[Depends(api_key_scheme)])
    async def get_result(request_id: str, request: Request) -> Dict[str, Any]:
        if not request_id.isalnum() or len(request_id) > 64:
            raise HTTPException(status_code=400, detail="invalid request id")
        detector: Detector = request.app.state.detector
        path = detector.config.result_dir / f"{request_id}.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail="result not found")
        return json.loads(path.read_text(encoding="utf-8"))

    @app.get("/v1/review", dependencies=[Depends(api_key_scheme)])
    async def pending_review(request: Request, limit: int = Query(default=100, ge=1, le=500)) -> Dict[str, Any]:
        detector: Detector = request.app.state.detector
        rows = detector.review.pending(limit)
        for row in rows:
            row["reason_codes"] = json.loads(row.pop("reason_codes_json"))
            row["evidence"] = json.loads(row.pop("evidence_json"))
        return {"items": rows, "count": len(rows)}

    @app.post("/v1/review/{request_id}", dependencies=[Depends(api_key_scheme)])
    async def resolve_review(request_id: str, payload: ReviewResolution, request: Request) -> Dict[str, Any]:
        detector: Detector = request.app.state.detector
        if not detector.review.resolve(request_id, payload.label, payload.note):
            raise HTTPException(status_code=404, detail="pending review case not found")
        return {"request_id": request_id, "status": "resolved", "label": payload.label}

    return app


app = create_app()
