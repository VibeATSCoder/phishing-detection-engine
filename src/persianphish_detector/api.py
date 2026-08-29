from __future__ import annotations

import json
import hmac
import hashlib
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from . import __version__
from .body_limit import RequestBodyLimitMiddleware
from .config import DetectorConfig
from .observability import (
    configure_tracing,
    instrument_app,
    set_build_info,
)
from .orchestrator import Detector
from .url_utils import canonical_url


MAX_REQUEST_BODY_BYTES = 14_000_000


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

    @model_validator(mode="after")
    def validate_total_reference_size(self) -> "DetectRequest":
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
        if selected_config.api_key and request.url.path not in {"/health", "/ready", "/metrics"}:
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
            "policy_production_ready": detector.artifact.policy.production_ready if detector.artifact else False,
            "agent_configured": detector.agent is not None,
            "browser_enabled": detector.browser is not None,
        }

    @app.get("/ready")
    async def ready(request: Request) -> JSONResponse:
        detector: Detector = request.app.state.detector
        model_ready = detector.artifact is not None
        tcn_ready = detector.tcn is not None
        agent_ready = await detector.agent.ready() if detector.agent else True
        ready_state = model_ready and tcn_ready and agent_ready
        return JSONResponse(
            status_code=200 if ready_state else 503,
            content={
                "ready": ready_state,
                "service_version": __version__,
                "model_loaded": model_ready,
                "tcn_loaded": tcn_ready,
                "agent_configured": detector.agent is not None,
                "agent_ready": agent_ready,
            },
        )

    @app.post("/v1/detect")
    async def detect(payload: DetectRequest, request: Request) -> Dict[str, Any]:
        detector: Detector = request.app.state.detector
        browser_payload = payload.browser_evidence.model_dump() if payload.browser_evidence else None
        agent_references = [item.model_dump(mode="json") for item in payload.agent_references]
        result = await detector.detect(payload.url, browser_payload, agent_references)
        return result.to_dict()

    @app.get("/v1/detect/{request_id}")
    async def get_result(request_id: str, request: Request) -> Dict[str, Any]:
        if not request_id.isalnum() or len(request_id) > 64:
            raise HTTPException(status_code=400, detail="invalid request id")
        detector: Detector = request.app.state.detector
        path = detector.config.result_dir / f"{request_id}.json"
        if not path.exists():
            raise HTTPException(status_code=404, detail="result not found")
        return json.loads(path.read_text(encoding="utf-8"))

    @app.get("/v1/review")
    async def pending_review(request: Request, limit: int = Query(default=100, ge=1, le=500)) -> Dict[str, Any]:
        detector: Detector = request.app.state.detector
        rows = detector.review.pending(limit)
        for row in rows:
            row["reason_codes"] = json.loads(row.pop("reason_codes_json"))
            row["evidence"] = json.loads(row.pop("evidence_json"))
        return {"items": rows, "count": len(rows)}

    @app.post("/v1/review/{request_id}")
    async def resolve_review(request_id: str, payload: ReviewResolution, request: Request) -> Dict[str, Any]:
        detector: Detector = request.app.state.detector
        if not detector.review.resolve(request_id, payload.label, payload.note):
            raise HTTPException(status_code=404, detail="pending review case not found")
        return {"request_id": request_id, "status": "resolved", "label": payload.label}

    return app


app = create_app()
