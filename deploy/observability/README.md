# Stack observability

Metrics, traces, and dashboards for all four PersianPhish components.

## What is collected, and what is deliberately not

This stack exists to avoid building a record of what people browse. The
observability plane holds to the same rule.

| Signal | Carries | Never carries |
|---|---|---|
| Metrics | Verdicts, stages, outcomes, latencies, score distributions, queue depths, token counts | URLs, hostnames, case identifiers |
| Traces | Verdict, stage, risk score, request id, **URL digest**, registrable domain | Full URLs, page HTML, prompts, completions, headers, cookies, form values |
| Extension diagnostics | Host, URL digest, verdict, timings, reason codes — in memory, on device | Anything transmitted anywhere |

`url.digest` is the first 16 hex characters of `SHA-256(canonical_url)`. The
canonicalization — lowercase scheme and host, default port dropped, query
sorted, fragment discarded — is implemented **three times**: in the detector's
and reviewer's `observability.py`, and in the extension's `diagnostics.js`. It
must stay byte-identical in all three or correlation across the escalation hop
silently breaks, so each Python side pins golden digests in its
`test_observability.py`, and the parity check below covers the JavaScript one.

The monitor is not part of this contract. It works in hostnames rather than
URLs and emits no digest at all.

The digest is one-way. An operator who already holds a URL can compute its
digest and find the case; the store alone cannot reveal the URL.

## Bringing it up

```bash
docker network create persianphish
docker compose -f deploy/observability/compose.observability.yaml up -d
```

Grafana lands on <http://127.0.0.1:3000> with the **PersianPhish Stack**
dashboard provisioned. Prometheus is on <http://127.0.0.1:9090>. Everything
binds to loopback and nothing authenticates by default — put a proxy in front
before exposing any of it.

## Enabling instrumentation in the services

Metrics are always on and cost nothing when the optional dependencies are
absent, in which case `/metrics` returns a comment and the code degrades to
no-ops. To get real metrics and traces, install the extra and point the service
at the collector:

```bash
python -m pip install -e '.[observability]'
export OTEL_EXPORTER_OTLP_ENDPOINT=http://127.0.0.1:4318
export OTEL_SERVICE_NAME=phishing-detection-engine
```

Tracing activates only when `OTEL_EXPORTER_OTLP_ENDPOINT` is set. Without it the
service runs untraced and untouched.

The monitor needs no extra dependency. Its exposition is written against the
standard library on purpose, so the repo keeps its two-dependency posture.

## Port conflict, before you hit it

The reviewer and the monitor's moderator panel **both default to 8090**. The
scrape config assumes the monitor has been moved:

```bash
export PANEL_PORT=8091
```

Change it there and in `prometheus.yml` together, or run them on separate hosts.

## Endpoints

| Service | Metrics | Auth |
|---|---|---|
| detector | `:8088/metrics` | exempt from `PPD_API_KEY`, same as `/health` |
| rag | `:8092/metrics` | unauthenticated; its key guard covers `/v1/` only |
| reviewer | `:8090/metrics` | unauthenticated; its key guard only covers `/api/` |
| monitor | `:8091/metrics` | unauthenticated; panel key guards only `/api/` |

All three carry bounded enumerations only, which is why they are scrapeable
without a key. They still should not be publicly reachable.

## The alerts, and why these ones

`alerts.yml` is written against the system's invariants rather than generic
service health. The recurring question is not "is it up" but "has it stopped
abstaining correctly":

- **CrawlFailureRateHigh** — `crawl_failed` is a correct verdict, but a
  sustained rate means the detector is answering "I could not look" to most
  traffic, usually from blocking or a broken Chromium pool.
- **SuspiciousRateHigh** / **OutOfDistributionRising** — the input mix has
  drifted from the calibration set. These fire before accuracy visibly degrades.
- **VerifierNeverDisagrees** — the skeptical second pass exists to override an
  over-eager analyst. Total agreement over six hours means it has stopped being
  an independent check.
- **ReviewQueueGrowing** — nothing drains this queue automatically; it is worked
  by a human, so growth is an operational signal rather than a bug.
- **MonitorAdjudicationFallingBehind** / **DiscoveryStalled** — the monitor can
  be up and healthy while discovering nothing, or while falling days behind on
  VirusTotal checks.
- **ReferenceLookupsMostlyEmpty** / **ReferenceScoresLow** — the reference index
  can be loaded and answering while no longer covering the traffic it sees. The
  reviewer needs `reference_quality >= 0.6` to escape the suspicious floor, and
  that quality is bounded above by the retrieval score, so a low median score
  means reviews will simply stop resolving.

Thresholds are starting points. Tune them once you have a week of baseline.

## Verifying the digest contract

The Python implementations are pinned by golden values in each repo's
`tests/test_observability.py`, so `pytest` catches any drift between them. The
JavaScript side is not reachable from pytest, so check it directly whenever
`diagnostics.js` changes:

```bash
node deploy/observability/check-digest-parity.mjs
```

It recomputes every golden digest through `diagnostics.js` and exits non-zero on
the first mismatch.

## Extension diagnostics

The extension is offline by invariant and stays that way. It keeps a 200-entry
in-memory ring buffer in the service worker, viewable under **Local
diagnostics** on the options page, with Refresh, Export JSON, and Clear. Nothing
is transmitted, nothing is persisted across a service-worker restart, and no
code path in `diagnostics.js` calls `fetch`. Export writes a file the user
explicitly asked for.

If a user reports a bad verdict, ask them to export. The digests in that file
join directly to the detector and reviewer traces for the same URL.
