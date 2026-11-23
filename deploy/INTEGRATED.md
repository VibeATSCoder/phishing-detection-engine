# Minimal integrated deployment

Stack 1.4.1 uses detector v3.11.1, reviewer v1.13.0, extension v3.14.0, and optional RAG v2.3.0. The component contract is recorded in [COMPATIBILITY.json](COMPATIBILITY.json).

## Concurrent review

The detector and internal services admit a burst of 100 concurrent scans. The integrated reviewer starts up to 100 review jobs, and the detector's shared reviewer transport holds 128 connections. RAG caps outbound API embeddings and CPU index searches separately, so a slow embedding does not hold the index slot. The standalone local encoder retains one lookup slot.

When a pipeline selects adjacent **RAG → Agent** stages, the detector submits one job. The reviewer starts suspect-only analysis and retrieves references concurrently. The verifier receives both the analyst output and the real reference comparison. Other pipeline orders still follow the selected order. In diagnostics, overlapping stage times can add up to more than the elapsed time.

| Setting | Default | Purpose |
| --- | --- | --- |
| `PPD_REVIEW_WORKERS` | `100` | Active integrated review jobs |
| `PPD_AGENT_MAX_CONNECTIONS` | `128` | Detector connections to the reviewer |
| `REVIEW_PENDING_EVIDENCE_BYTES` | `256000000` | In-memory evidence limit across active and queued reviews |
| `RAG_EMBED_CONCURRENCY` | `32` | Concurrent requests to the configured embedding API |
| `RAG_SEARCH_CONCURRENCY` | `2` | Concurrent API-mode index searches |
| `RAG_QUEUE_TIMEOUT_S` | `15` | Maximum wait for a retrieval slot |
| `PPD_REFERENCE_TIMEOUT_S` | `35` | Detector deadline for standalone reference retrieval |
| `PPD_PARALLEL_REVIEW` | `1` | Combine adjacent RAG and Agent stages |

The limits set how much traffic the stack can admit. Completion times depend on crawl latency, index CPU and memory bandwidth, and the configured providers' capacity. Overloaded stages report a bounded unavailable result.

## Trusted URLs and repeat visits

The detector checks local phishing intelligence first. Curated first-party pages such as the Google homepages can then return immediately for the default or a custom pipeline. Each shortcut lists the selected stages as skipped.

An exact HTTPS URL earns a reusable result when a fresh, successful server crawl reaches a legitimate Decision result with at least 0.90 confidence and at most 0.03 risk. It must have clean observed evidence and the same final URL. Login forms, redirects, query strings, fragments, and URLs with ambiguous path encoding stay on the normal scan path.

The detector keeps eligible results in the existing data volume. Each result expires one hour after verification by default, with a separate 24-hour window for verified RAG reference homepages. Hits do not extend expiry. Changing stage order, Decision settings, provider/model, or detector build requires a fresh result for that policy. The full installer imports the active RAG index's validated homepage URLs as candidates. Each candidate receives a live scan on its first eligible visit before it can use the longer window.

| Setting | Default |
| --- | --- |
| `PPD_TRUSTED_URLS_ENABLED` | `1` |
| `PPD_TRUSTED_URL_TTL_S` | `3600` |
| `PPD_TRUSTED_RAG_URL_TTL_S` | `86400` |
| `PPD_TRUSTED_URL_MIN_CONFIDENCE` | `0.90` |
| `PPD_TRUSTED_URL_MAX_RISK` | `0.03` |

For a fresh check through the API, send `"use_trusted_urls": false` in the `POST /v1/detect` body. The response identifies reuse as `trusted_url_cache` and reports the source, risk, confidence, and expiration.

This bundle runs two services:

- `detector` on `127.0.0.1:8088`: the only final decision API.
- `review` on `127.0.0.1:8090`: the advisory UI/API, called only for usable uncertain detector results.

The detector supplies its already-crawled DOM to the reviewer. The reviewer sends only bounded, sanitized structural/textual evidence to OpenRouter. Raw HTML is not stored.

## Requirements

- Docker Engine 24+ with the Compose v2 plugin.
- Outbound HTTPS access for crawling and OpenRouter.
- An OpenRouter API key. No host Python, browser, Node.js, model runtime, or GPU is required.

## Start with one command (recommended)

No checkout, no build, no `gh`. This downloads every release artefact, loads
each image, writes one aggregated `.env`, and starts the stack:

```bash
curl -fsSL https://github.com/VibeATSCoder/phishing-detection-engine/releases/download/v3.11.1/install.sh | bash
```

It stops and tells you what to fill in the first time, because
`OPENROUTER_API_KEY` and `INTERNAL_REVIEW_API_KEY` have no sensible defaults.
Set them in `persianphish/deploy/.env`, then:

```bash
cd persianphish && bash deploy/deploy.sh
```

Options: `--with-references` also fetches the retrieval service (about 3 GB
more, and it needs `RAG_INDEX_HOST_PATH` set); `--download-only` fetches and
loads without starting anything; `--dir` installs somewhere other than
`./persianphish`.

### Upgrade an existing installation with a GitHub token

Run these commands from the directory containing `deploy/.env`. Use
`--dir /path/to/persianphish` to select another installation directory.

```bash
curl -fL --progress-bar --connect-timeout 120 --max-time 86400 \
  -o install.sh https://github.com/VibeATSCoder/phishing-detection-engine/releases/download/v3.11.1/install.sh
bash install.sh --upgrade --ask-token --full
```

The token prompt hides input. A classic token needs `repo` scope. A fine-grained
token needs access to the private reviewer and RAG repositories and
**Contents: Read-only** permission. For automation, supply `GITHUB_TOKEN`
through the environment and omit `--ask-token`. The `--token` option also works.

An interactive upgrade offers to keep or edit the Decision model, review agent,
and RAG embedding settings. The provider keys are separate from the GitHub token.
Use `--no-prompt` to retain settings for unattended upgrades. `--full` includes
the reference service. An installation already using the internal RAG service
keeps it enabled with `--upgrade` alone.

For extensions on another computer, enter the HTTPS proxy origin. When
`CADDY_DOMAIN` is set in `deploy/.env`, `deploy.sh --show-config` lists that
origin alongside the URLs used for local server checks.

Downloads show progress and resume from partial files on a rerun. The default
is 24 hours per asset transfer attempt, with retries and a 15-minute idle
limit. Set `--download-timeout SECONDS` to change the transfer timeout.
Docker load displays its layer output. Service startup reports progress and
allows 30 minutes per service by default. Set `--health-timeout SECONDS`
to change the startup wait.

### Configure provider APIs on the installed stack

When the extension reports **Configure these stages on the detector first:
Decision model**, download the current installer above, then run it from the
directory containing `deploy/.env`.

```bash
bash install.sh --configure-providers --full
```

This uses the existing deployment files and local images. A GitHub token is
unnecessary for this command. Provider URLs, model IDs, and keys are saved in
`deploy/.env`. The installed deployment script then applies the settings.

- **Decision model** asks for the base URL, model ID, API format and key.
  AvalAI Jev uses `https://api.avalai.ir/v1`, `jev-latest`, and `decisions`.
- **Review agent** asks for its own language model URL, model ID, and key.
- **RAG embeddings** asks whether to use local BGE-M3 or an API. Select `api`
  to enter the URL, key and model ID for a 1,024-dimensional BGE-M3 endpoint.

Select **Test connection** in the extension after the stack starts.

## Start from released images by hand

If you would rather do it step by step, download the image artefacts and the
stack bundle from the two releases into one directory, unpack the bundle, and
run the script:

```bash
tar -xzf persianphish-stack-1.4.1-deploy.tar.gz     # compose files and this guide
cp deploy/stack.env.example deploy/.env             # then set the two keys
bash deploy/deploy.sh
```

`deploy.sh` finds the artefacts, loads them, refuses to start unless the two
keys are set, waits for both containers to report healthy, and prints the
endpoints. Checksums are not verified unless you pass `--verify`.

## Start from source

Clone the two backend repositories as siblings:

```bash
git clone https://github.com/VibeATSCoder/phishing-detection-engine.git
git clone https://github.com/VibeATSCoder/agentic-phishing-review.git
cd phishing-detection-engine
```

For private repositories, authenticate Git before cloning. From
`phishing-detection-engine`:

```bash
cp .env.example .env
```

Set these two values in `.env`:

```dotenv
OPENROUTER_API_KEY=your-openrouter-key
INTERNAL_REVIEW_API_KEY=a-long-random-internal-secret
```

Generate the internal secret with `openssl rand -hex 32`. Optionally set `PPD_API_KEY` to require `X-API-Key` on detector endpoints other than health/readiness.

```bash
docker compose -f deploy/compose.yaml config --quiet
docker compose -f deploy/compose.yaml up -d --build
docker compose -f deploy/compose.yaml ps
curl --fail http://127.0.0.1:8088/ready
```

Submit a URL:

```bash
curl --fail -X POST http://127.0.0.1:8088/v1/detect \
  -H 'content-type: application/json' \
  -d '{"url":"https://example.com/"}'
```

If `PPD_API_KEY` is set, add `-H 'X-API-Key: your-key'`. The English review UI is at `http://127.0.0.1:8090/`.

To connect `phishingshield-persian` v3.8.1, open the extension's Options page,
enable backend review, use `http://127.0.0.1:8088`, and enter the same
`PPD_API_KEY` configured here. The extension sends only suspicious URLs and
never sends page HTML, cookies, headers, or form values.

## Optional JEV screening

Set these values in `deploy/.env` to run AvalAI's TypeSafe Jev by default:

```dotenv
PPD_JEV_ENABLED=1
PPD_JEV_API_FORMAT=decisions
PPD_JEV_BASE_URL=https://api.avalai.ir/v1
PPD_JEV_MODEL=jev-latest
PPD_JEV_API_KEY=
```

Set `PPD_JEV_API_KEY` using your AvalAI key. The Decisions client calls
`POST /v1/decisions` and asks four typed risk questions and one label question.
The reply's label confidence comes from the provider. The detector validates
each named answer and routes missing or invalid answers to review. See the
[AvalAI TypeSafe documentation](https://docs.avalai.ir/en/providers/typesafe).

Use `PPD_JEV_API_FORMAT=chat_completions` for an OpenAI-compatible chat model
that returns the JEV score object requested by the detector's prompt.
Both formats send the hostname, bounded visible text, and selected
structural counts. Decisions does not send raw HTML, full URLs or form values.

Set `PPD_FAST_MODELS_ENABLED=0` for JEV followed by deep review without RF/TCN.
The running Compose stack must have a reachable reviewer, with RAG configured
if reference retrieval is desired. A request to `POST /v1/detect` can use
`"use_rf": false` to skip RF/TCN for that call and `"use_jev": true` to select
the configured screener. Omit either key to use the service default.

In an ordered pipeline, a legitimate Decision result skips every remaining
stage when confidence is at least `0.80`, risk is at most `0.05`, and the page
passes the observed-risk checks. Set `PPD_JEV_PIPELINE_EARLY_CLEAR=0` to disable
this default or use the per-request Decision overrides. Legacy `use_jev` and
`use_rf` requests keep the separate `PPD_JEV_SHORT_CIRCUIT_LEGIT` setting for
standalone clearance. Confirmed threat intelligence keeps priority in the
legacy flow, and unusable crawl evidence yields `crawl_failed`.

Read category scores, confidence, model and status under `evidence_summary.jev`.
The detector reports `latency_ms.total` for work through the verdict.
It also reports crawl time, domain facts, feature extraction, combined
RF/TCN time, Jev time and agent time when applicable. Under crawl, the
`http`, `browser` and `browser_input` timings identify how evidence was
obtained. These are included in `crawl`. An HTTP 403 or a recognized VPN
access notice ends the content pipeline with `crawl_failed` before a browser
retry or a model or reviewer call. VPN notices can arrive with HTTP 200 and
appear as `vpn_access_restricted` in the reason codes.

Read the RF/TCN verdict in `evidence_summary.fast_verdict` and scores in
`model_scores`. For an escalated case, `evidence_summary.agent_review`
contains the RAG reference matches, reviewer timings, the analyst and verifier
verdicts and scores, and the reviewer's reconciled candidate. The reviewer
returns the same per-stage measurements in `result.timings_ms` and the
two pass outcomes in `result.review_passes` when polling
`GET /api/v1/analyses/{analysis_id}`. Those reviewer timings are included
in the detector's `latency_ms.agent`, which also measures the HTTP and polling
overhead. Read the detector's final decision in `verdict`.

With `PPD_AGENT_PREFETCH_REFERENCES=1`, the detector asks the reviewer to
begin local reference retrieval during Jev when the current policy already
requires deep review. It does this only for usable evidence and when the caller
supplied no references. The reviewer still receives the complete Jev outcome.
The `rag` reviewer timing measures the wait for references, which can be near
zero if the lookup finishes during Jev. Older reviewer deployments fall back
to retrieving references during normal review.

Keep `OPENROUTER_MODEL=google/gemma-4-31b-it` for standard reviewer routing.
Set `OPENROUTER_MODEL=google/gemma-4-31b-it:nitro` to test OpenRouter's
throughput-oriented route for the same model on both review passes. Measure
stage latency and final verdicts on the same inputs before switching a runtime.

If RF/TCN did not run, its `model_scores` are null and the top-level
`risk_score` is the neutral fallback 0.5 unless a configured local JEV model
issued the terminal phishing verdict.

For offline JEV scoring, set `PPD_JEV_LOCAL_MODEL_PATH` to the trusted model
artifact. The local model can run alone or before the configured provider. To
use it in a container, include the artifact in the detector image or mount it
read-only at that container path. The detector reports the model result under
`evidence_summary.jev_local`, separately from the RF/TCN and provider scores.

The local model sends risky and failed scores to review by default. It does
not issue standalone clearances. `PPD_JEV_LOCAL_AUTO_FLAG=1` allows it to issue
terminal phishing verdicts above its saved threshold. Evaluate false positives
on representative data before enabling that option.

To enable the local guard by default once the artifact is available inside the
detector container:

```dotenv
PPD_JEV_ENABLED=1
PPD_JEV_LOCAL_MODEL_PATH=/app/artifacts/v3/jev_local_isolated.joblib
PPD_JEV_LOCAL_AUTO_FLAG=0
```

Train an artifact from the frozen feature dataset and verify its thresholds on
the separate test split:

```bash
PYTHONPATH=src python scripts/train_local_jev.py --output /path/to/jev_local_v1.joblib
PYTHONPATH=src python scripts/evaluate_fast_stage.py --local-jev /path/to/jev_local_v1.joblib
```

Use `PPD_MODEL_PATH` for the local RF/TCN bundle, `PPD_AGENT_BASE_URL` for the
reviewer service, and `OPENROUTER_BASE_URL` / `OPENROUTER_MODEL` for the
reviewer's LLM. Set `RAG_BASE_URL` on the reviewer to choose the references
service. Its embedding endpoint and model are configurable through
`RAG_EMBED_API_BASE` and `RAG_EMBED_MODEL`. The embedding model must match
the selected reference index.

## Verify without spending OpenRouter tokens

The test override replaces OpenRouter with a deterministic in-container test double while exercising RF, TCN, API validation, async submit/poll, evidence extraction, both agent passes, reconciliation, and persistence:

```bash
OPENROUTER_API_KEY=test INTERNAL_REVIEW_API_KEY=integration-secret \
docker compose -f deploy/compose.yaml -f deploy/compose.test.yaml up -d --build
python scripts/smoke_integrated.py
docker compose -f deploy/compose.yaml -f deploy/compose.test.yaml down -v
```

PowerShell:

```powershell
$env:OPENROUTER_API_KEY = "test"
$env:INTERNAL_REVIEW_API_KEY = "integration-secret"
docker compose -f deploy/compose.yaml -f deploy/compose.test.yaml up -d --build
python scripts/smoke_integrated.py
docker compose -f deploy/compose.yaml -f deploy/compose.test.yaml down -v
```

## Operate

```bash
docker compose -f deploy/compose.yaml logs --tail=200 detector review
docker compose -f deploy/compose.yaml pull
docker compose -f deploy/compose.yaml up -d --build
docker compose -f deploy/compose.yaml down
```

Named volumes `detector-data` and `review-data` hold SQLite audit state. Back them up before upgrades. `down` preserves them; `down -v` deletes them and is only appropriate for disposable tests.

Both ports bind to loopback. To serve remotely, keep the containers private and expose only the detector through a TLS reverse proxy with authentication, a 14 MB request-body limit, rate limiting, and sensible timeouts. The application also enforces streamed-body limits itself. Do not place keys in the image, Compose file, Git, logs, or API request bodies.

## Optional: reference retrieval

The reviewer can ask a retrieval service which known-legitimate pages a suspect
resembles, and use them as comparison references. This is off by default.

It matters more than "optional" suggests. The reconciliation policy floors every
verdict at `suspicious` when reference quality is below 0.6, and reference
quality comes entirely from the references supplied with the review. With none,
that floor is always active: the LLM verdict is computed, paid for, and then
discarded. Turning this on is what lets a review resolve to `legitimate`.

It is off by default because the index is a multi-gigabyte directory mounted
from the host, not baked into the image.

```bash
# once, to build the fast-load cache in the index directory
RAG_INDEX_HOST_PATH=/path/to/Embedding_Index \
  docker compose -f deploy/compose.yaml -f deploy/compose.references.yaml \
  run --rm --volume /path/to/Embedding_Index:/data/index rag \
  python scripts/build_index_cache.py

RAG_INDEX_HOST_PATH=/path/to/Embedding_Index \
RAG_BASE_URL=http://rag:8092 \
  docker compose -f deploy/compose.yaml -f deploy/compose.references.yaml up -d
```

`RAG_BASE_URL` is what actually switches it on; the overlay only adds the
service. Confirm the reviewer picked it up:

```bash
curl -s localhost:8090/ready | grep reference_service_configured
```

First start is slow: `/ready` returns 503 until BGE-M3 and the index are loaded,
which is why the healthcheck allows three minutes before it starts failing.

Measured on 20 simulated clones, references clear the hard `suspicious` floor
about half the time and reach the bar a `legitimate` verdict needs about one
time in ten. Whether 0.75 is the right bar for text-only references is an open
policy question, not a settled one.

Any retrieval failure yields no references rather than an error, so the service
being down degrades reviews to the same behaviour as not running it at all.

## Failure behavior

- Invalid/private URLs fail before crawling.
- Blocked, empty, challenge, non-HTML, and timeout evidence returns `crawl_failed`; it is never sent to the agent.
- Agent timeout, malformed output, unsupported codes, or service failure returns `suspicious` and queues human review.
- Confident RF/TCN results do not spend OpenRouter calls.
- OpenRouter scores are advisory and are never blended into the calibrated RF/TCN score.
- Reference retrieval failing, timing out, or being absent yields no references; reviews continue and are floored at `suspicious`.

## Manual installation and extension testing

Download [install.sh](https://github.com/VibeATSCoder/phishing-detection-engine/releases/download/v3.11.1/install.sh)
into your installation directory. Run it in a terminal so it can show the
release links and check for local files.

```bash
bash install.sh --manual --full
```

Use these release assets if you are downloading on a separate computer.

| Component | Assets |
| --- | --- |
| Detector | [Docker image and checksum](https://github.com/VibeATSCoder/phishing-detection-engine/releases/tag/v3.11.1) |
| Stack | [Deployment bundle](https://github.com/VibeATSCoder/phishing-detection-engine/releases/download/v3.11.1/persianphish-stack-1.4.1-deploy.tar.gz) |
| Reviewer | [Docker image and checksum](https://github.com/VibeATSCoder/agentic-phishing-review/releases/tag/v1.13.0) |
| RAG | [Image parts, checksums, and loader](https://github.com/VibeATSCoder/phishing-rag-service/releases/tag/v2.3.0) |
| Reference index | [Index parts and checksum](https://github.com/VibeATSCoder/phishing-detection-engine/releases/tag/rag-index-2.0.0) |
| Browser extension | [Chrome/Edge ZIP](https://github.com/VibeATSCoder/phishingshield-persian/releases/download/v3.14.0/phishingshield-persian-v3.14.0.zip) |

The installer prompts for the reviewer provider and offers a separate Decision
model endpoint. For AvalAI Jev use base URL `https://api.avalai.ir/v1`, format
`decisions`, and model `jev-latest`. Supply the provider key to the installer or
set `PPD_JEV_API_KEY` in `deploy/.env`. The extension uses the detector's
`PPD_API_KEY`. A configured Decision model is callable from a selected pipeline
when `PPD_JEV_ENABLED=0`, which keeps it off in the server's default pipeline.
For existing installations, the installer uses the versioned deployment bundle
and retains provider keys from the existing `deploy/.env`. A full install records the selected RAG image version there.

Unzip the extension on the browser computer. In `chrome://extensions` or
`edge://extensions`, enable Developer mode and select **Load unpacked**. Open
the extension's options and enable backend review. Enter the detector origin
and its API key. Check **Send every page to the backend** and **Customize backend
stages** to test precisely the selected backend stages. Check the stages you
want and move them into order. **Test connection** checks the detector's
configuration. Open a Persian-language test page, then refresh **Local diagnostics** to see the
stages that completed, were unavailable, or were skipped, plus their timings.

A definitive verdict ends the pipeline. RAG retrieves reference matches and
leaves the verdict suspicious if there are no other conclusive stages.
Agent-only runs disable automatic retrieval, and an agent that runs before
RAG cannot use results from that later stage. Decision-only runs follow the
configured provider's conservative clearance policy. Failed crawls skip all
selected stages. If **Send every page** is off, the browser uses its offline
URL model first and forwards only locally suspicious pages.

API clients can send the same order directly.

```json
{"url":"https://example.com/","pipeline":["rf","decision","rag","agent"]}
```

The extension requests live stage updates through
`Accept: application/x-ndjson` on `POST /v1/detect`. The stream carries stage
names and statuses, followed by the same result available as regular JSON.
Clients requesting JSON still receive one response. The extension displays a
short quiz and waiting message with older servers while it awaits the result.

## Diagnose a slow or inconclusive scan

The diagnostics export includes the crawl status and HTTP response code when
available. A blocked or unusable crawl ends the scan before inference. HTTP
403 means the site declined the detector's request.

Enable **Override Decision model thresholds** in Extension options to set the
risk at which the stage escalates, the minimum confidence required to clear a
page, and the maximum risk for an early legitimate clearance. New overrides
enable clearance by default. The checkbox can require later stages even when
confidence is high. Clearance requires a legitimate model label, usable
evidence, and no observed risk veto.
The Decision column shows the provider risk, confidence and routing checks.

The review agent defaults to 25 seconds per model call and 55 seconds for the
whole review. The reviewer reads `REVIEW_LLM_TIMEOUT_S` and `REVIEW_BUDGET_S`
from `deploy/.env`. Upgrading updates the old 15/35-second default pair.
A timed-out model call ends that pass and leaves the page under suspicion.
The diagnostics show the failing pass.

The installer checks any selected embedding endpoint with a synthetic query
before restarting the services. It shows HTTP failures and checks that the
response contains a usable 1024-dimensional vector. Choose the same BGE-M3
model as the index. If the probe fails, interactive setup can retry with a
new API, switch to local BGE-M3, or exit before restarting the services.
On an installed stack, repeat provider setup with
`bash install.sh --configure-providers --full`.

A full deployment runs a real reference lookup from the reviewer container
after RAG reports ready. Run `bash deploy/deploy.sh --check-retrieval` from the
installation directory to repeat it. A completed lookup can return zero
matches. HTTP 500 from RAG means the service reached its lookup handler and
failed during the request. The detector carries the upstream status into the
extension diagnostics.

The AvalAI `gemma-4-31b-it` reviewer uses the provider's JSON Schema response
format with thinking disabled for the bounded analyst and verifier outputs.
An exhausted output budget is reported as `analyst_output_token_limit` or
`verifier_output_token_limit`.
