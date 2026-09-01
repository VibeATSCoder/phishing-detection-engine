"""OpenTelemetry traces and Prometheus metrics for the detector.

Privacy contract
----------------
Raw URLs never enter telemetry. Every URL is reduced to a truncated SHA-256
digest of its canonical form plus its registrable domain. That is enough to
count, group, join across services, and locate a specific case when the
operator already holds the URL, without the telemetry store itself becoming a
record of what users browsed.

The same rules that apply to the review queue apply here: no raw HTML, no
headers, no cookies, no form values, no screenshots, no script bodies.

Both dependency groups are optional. If ``prometheus_client`` or the
OpenTelemetry SDK is not installed the module degrades to no-ops so the
service starts and behaves exactly as it did before instrumentation.
"""

from __future__ import annotations

import hashlib
import os
from contextlib import contextmanager
from typing import Any, Iterator, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

from .url_utils import registrable_domain

try:  # pragma: no cover - exercised by the extras install
    from prometheus_client import (
        CONTENT_TYPE_LATEST,
        CollectorRegistry,
        Counter,
        Gauge,
        Histogram,
        generate_latest,
    )

    PROMETHEUS_AVAILABLE = True
except ImportError:  # pragma: no cover
    PROMETHEUS_AVAILABLE = False
    CONTENT_TYPE_LATEST = "text/plain; charset=utf-8"

try:  # pragma: no cover - exercised by the extras install
    from opentelemetry import trace
    from opentelemetry.trace import SpanKind, Status, StatusCode

    OTEL_AVAILABLE = True
except ImportError:  # pragma: no cover
    OTEL_AVAILABLE = False


SERVICE_NAME = "phishing-detection-engine"

# Latency buckets tuned to the observed shape of this pipeline: the fast path
# (intel match, cached model) resolves in single-digit milliseconds, an HTTP
# crawl lands near one second, a Chromium render several seconds, and an agent
# escalation tens of seconds.
_LATENCY_BUCKETS = (
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
    2.5, 5.0, 10.0, 20.0, 30.0, 60.0, 120.0,
)
_SCORE_BUCKETS = (0.0, 0.05, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95, 1.0)


class _NullMetric:
    """Stand-in used when prometheus_client is not installed."""

    def labels(self, *args: Any, **kwargs: Any) -> "_NullMetric":
        return self

    def inc(self, amount: float = 1) -> None:
        return None

    def observe(self, amount: float) -> None:
        return None

    def set(self, value: float) -> None:
        return None


_NULL = _NullMetric()


class Metrics:
    """Prometheus collectors for the detector.

    Instantiated once per process. Every collector is a no-op when
    prometheus_client is absent, so call sites never need a guard.
    """

    def __init__(self, registry: Optional["CollectorRegistry"] = None) -> None:
        self.enabled = PROMETHEUS_AVAILABLE
        if not self.enabled:
            self.registry = None
            self.detections = _NULL
            self.detection_duration = _NULL
            self.stage_duration = _NULL
            self.model_score = _NULL
            self.ood_fraction = _NULL
            self.intel_matches = _NULL
            self.agent_calls = _NULL
            self.agent_duration = _NULL
            self.agent_reconciliation = _NULL
            self.crawl_outcomes = _NULL
            self.review_queue_depth = _NULL
            self.http_requests = _NULL
            self.http_duration = _NULL
            self.build_info = _NULL
            return

        self.registry = registry or CollectorRegistry()

        self.detections = Counter(
            "ppd_detections_total",
            "Detections completed, by final verdict and the stage that decided it.",
            ["verdict", "stage", "crawl_status"],
            registry=self.registry,
        )
        self.detection_duration = Histogram(
            "ppd_detection_duration_seconds",
            "Wall-clock time for a full detection, by final verdict.",
            ["verdict"],
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.stage_duration = Histogram(
            "ppd_stage_duration_seconds",
            "Per-stage time within a detection (crawl, facts, agent).",
            ["stage"],
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.model_score = Histogram(
            "ppd_model_score",
            "Distribution of model scores. Watch for drift against training.",
            ["model"],
            buckets=_SCORE_BUCKETS,
            registry=self.registry,
        )
        self.ood_fraction = Histogram(
            "ppd_ood_fraction",
            "Out-of-distribution fraction reported by the policy gate.",
            buckets=_SCORE_BUCKETS,
            registry=self.registry,
        )
        self.intel_matches = Counter(
            "ppd_intel_matches_total",
            "Exact local intelligence hits, by feed source and verdict.",
            ["source", "verdict"],
            registry=self.registry,
        )
        self.agent_calls = Counter(
            "ppd_agent_calls_total",
            "Escalations to the agentic reviewer, by outcome.",
            ["outcome"],
            registry=self.registry,
        )
        self.agent_duration = Histogram(
            "ppd_agent_duration_seconds",
            "Time spent waiting on the agentic reviewer, including polling.",
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.agent_reconciliation = Counter(
            "ppd_agent_reconciliation_total",
            "How the detector reconciled the reviewer's advisory verdict.",
            ["agent_verdict", "final_verdict", "corroborated"],
            registry=self.registry,
        )
        self.crawl_outcomes = Counter(
            "ppd_crawl_outcomes_total",
            "Crawl attempts by evidence source and resulting quality status.",
            ["source", "status"],
            registry=self.registry,
        )
        self.review_queue_depth = Gauge(
            "ppd_review_queue_depth",
            "Unresolved cases currently sitting in the SQLite review queue.",
            registry=self.registry,
        )
        self.http_requests = Counter(
            "ppd_http_requests_total",
            "HTTP requests served by the detector API.",
            ["method", "route", "status"],
            registry=self.registry,
        )
        self.http_duration = Histogram(
            "ppd_http_request_duration_seconds",
            "HTTP request latency for the detector API.",
            ["method", "route"],
            buckets=_LATENCY_BUCKETS,
            registry=self.registry,
        )
        self.build_info = Gauge(
            "ppd_build_info",
            "Always 1. Labels carry the running service and model versions.",
            ["version", "model_version", "artifact_production_ready"],
            registry=self.registry,
        )

    def render(self) -> bytes:
        if not self.enabled or self.registry is None:
            return b"# prometheus_client is not installed\n"
        return generate_latest(self.registry)


METRICS = Metrics()


# --- cross-service digest contract -----------------------------------------
# This canonicalization is duplicated verbatim in the reviewer and the monitor.
# It deliberately does NOT reuse each repo's own normalize/canonical helpers:
# those differ in small ways, and a digest that does not match byte-for-byte
# across services cannot be joined in a trace or a dashboard. Change it in one
# repo only if you change it in all three, and treat that as a breaking change
# to historical telemetry.
def telemetry_canonical_url(url: str) -> str:
    """Lowercased scheme/host, default port dropped, query sorted, no fragment."""
    parsed = urlsplit(url.strip())
    scheme = parsed.scheme.lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    if port is not None and not (
        (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    ):
        host = f"{host}:{port}"
    query = "&".join(
        f"{key}={value}"
        for key, value in sorted(parse_qsl(parsed.query, keep_blank_values=True))
    )
    return urlunsplit((scheme, host, parsed.path or "/", query, ""))


def url_digest(url: str) -> str:
    """Stable, non-reversible identifier for a URL.

    Canonicalizes first so the same page reached by trivially different
    spellings produces the same digest, and so the detector, reviewer, and
    monitor all produce the *same* digest for the same URL. Truncated to 16 hex
    characters: collisions stay negligible at this volume, and it is short
    enough to read in a log line or a Grafana table.
    """
    try:
        canonical = telemetry_canonical_url(url)
    except Exception:
        canonical = url.strip().lower()
    return hashlib.sha256(canonical.encode("utf-8", errors="replace")).hexdigest()[:16]


def url_labels(url: str) -> dict[str, str]:
    """The only URL-derived fields permitted in telemetry."""
    try:
        domain = registrable_domain(url)
    except Exception:
        domain = ""
    return {"url.digest": url_digest(url), "url.registrable_domain": domain}


def _tracer() -> Any:
    if not OTEL_AVAILABLE:
        return None
    return trace.get_tracer(SERVICE_NAME)


@contextmanager
def span(name: str, **attributes: Any) -> Iterator[Any]:
    """Start a span if OpenTelemetry is installed, otherwise do nothing.

    Attribute values that are None are dropped rather than stringified, so a
    missing measurement never shows up as the literal "None" in a trace.
    """
    tracer = _tracer()
    if tracer is None:
        yield None
        return
    with tracer.start_as_current_span(name, kind=SpanKind.INTERNAL) as current:
        for key, value in attributes.items():
            if value is not None:
                current.set_attribute(key, value)
        try:
            yield current
        except Exception as exc:
            current.set_status(Status(StatusCode.ERROR, type(exc).__name__))
            current.record_exception(exc)
            raise


def record_detection(result: Any) -> None:
    """Record one completed detection.

    Called from the single place every DetectionResult is constructed, so it
    sees fast-path exits, crawl failures, and agent-reconciled verdicts alike.
    """
    verdict = getattr(result.verdict, "value", str(result.verdict))
    crawl_status = getattr(result.crawl_status, "value", str(result.crawl_status))
    METRICS.detections.labels(
        verdict=verdict, stage=result.stage, crawl_status=crawl_status
    ).inc()

    latency = result.latency_ms or {}
    total = latency.get("total")
    if total is not None:
        METRICS.detection_duration.labels(verdict=verdict).observe(total / 1000.0)
    for stage_name, millis in latency.items():
        if stage_name != "total" and millis is not None:
            METRICS.stage_duration.labels(stage=stage_name).observe(millis / 1000.0)

    for model_name, score in (result.model_scores or {}).items():
        if score is not None:
            METRICS.model_score.labels(model=model_name).observe(float(score))

    current = trace.get_current_span() if OTEL_AVAILABLE else None
    if current is not None and current.is_recording():
        current.set_attribute("detector.verdict", verdict)
        current.set_attribute("detector.stage", result.stage)
        current.set_attribute("detector.crawl_status", crawl_status)
        current.set_attribute("detector.risk_score", float(result.risk_score))
        current.set_attribute("detector.request_id", result.request_id)
        for key, value in url_labels(result.url).items():
            current.set_attribute(key, value)
        if result.reason_codes:
            current.set_attribute("detector.reason_codes", ",".join(result.reason_codes[:16]))


def configure_tracing(service_version: str = "") -> bool:
    """Wire up OTLP export when an endpoint is configured.

    Controlled entirely by the standard OpenTelemetry environment variables;
    absent ``OTEL_EXPORTER_OTLP_ENDPOINT`` this returns False and the service
    runs untraced. Returns whether a provider was installed.
    """
    if not OTEL_AVAILABLE or not os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
        return False
    try:  # pragma: no cover - requires the sdk extra
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor
    except ImportError:
        return False

    resource = Resource.create(
        {
            "service.name": os.getenv("OTEL_SERVICE_NAME", SERVICE_NAME),
            "service.version": service_version,
        }
    )
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
    trace.set_tracer_provider(provider)
    return True


def set_build_info(
    service_version: str, model_version: str, production_ready: bool
) -> None:
    """Publish the running versions as gauge labels.

    Called once the artifact is loaded rather than at import time, so
    ``model_version`` reflects the artifact actually in memory. Exposing
    ``production_ready`` here means a dashboard can show, at a glance, that the
    loaded artifact still declares itself unfit for production.
    """
    METRICS.build_info.labels(
        version=service_version or "unknown",
        model_version=model_version or "unknown",
        artifact_production_ready=str(bool(production_ready)).lower(),
    ).set(1)


def instrument_app(app: Any) -> None:
    """Add request metrics and a ``/metrics`` endpoint to a FastAPI app.

    The route label uses the matched path template, never the raw path, so a
    parameterised route cannot explode cardinality or leak an identifier into
    a metric label.
    """
    import time as _time

    from fastapi import Response

    @app.middleware("http")
    async def _observe_requests(request: Any, call_next: Any) -> Any:
        started = _time.perf_counter()
        status = 500
        try:
            response = await call_next(request)
            status = response.status_code
            return response
        finally:
            route = request.scope.get("route")
            template = getattr(route, "path", None) or "unmatched"
            elapsed = _time.perf_counter() - started
            METRICS.http_requests.labels(
                method=request.method, route=template, status=str(status)
            ).inc()
            METRICS.http_duration.labels(method=request.method, route=template).observe(elapsed)

    @app.get("/metrics", include_in_schema=False)
    async def _metrics() -> Response:
        return Response(content=METRICS.render(), media_type=CONTENT_TYPE_LATEST)
