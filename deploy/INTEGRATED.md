# Minimal integrated deployment

Compatibility set: detector **v3.8.2**, reviewer **v1.11.0**, optional extension client **v3.7.0**.8.1**, reviewer **v1.11.0**, optional extension client **v3.6.0**. The exact contract is recorded in `COMPATIBILITY.json`.

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
curl -fsSL https://raw.githubusercontent.com/VibeATSCoder/phishing-detection-engine/main/deploy/install.sh | bash
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

### Credentials

Public repositories need none. For private ones, either shape works:

```bash
export GITHUB_TOKEN=ghp_...                    # token alone
export GITHUB_USER=you GITHUB_TOKEN=ghp_...    # username and token
```

The installer tries the public download URL first and only falls back to the
authenticated API. That order matters: the browser download URL answers 404 for
a token rather than a useful error, because it expects a session cookie, so a
private asset has to be resolved to an asset id and pulled from the API.

Downloads resume. A dropped connection continues where it stopped rather than
starting a 699 MB file again.

## Start from released images by hand

If you would rather do it step by step, download the image artefacts and the
stack bundle from the two releases into one directory, unpack the bundle, and
run the script:

```bash
tar -xzf persianphish-stack-1.1.0-deploy.tar.gz     # compose files and this guide
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

Set these values in `deploy/.env` to run the screener by default:

```dotenv
PPD_JEV_ENABLED=1
PPD_JEV_BASE_URL=https://provider.example/v1
PPD_JEV_MODEL=your-model
PPD_JEV_API_KEY=
```

The endpoint must implement OpenAI-compatible chat completions and return the
JEV score object requested by the detector's prompt. The detector sends a host,
bounded page text and a summary of structural signals. A CLEF or other custom
model can sit behind an endpoint that translates its output to that contract.

Set `PPD_FAST_MODELS_ENABLED=0` for JEV followed by deep review without RF/TCN.
The running Compose stack must have a reachable reviewer, with RAG configured
if reference retrieval is desired. A request to `POST /v1/detect` can use
`"use_rf": false` to skip RF/TCN for that call and `"use_jev": true` to select
the configured screener. Omit either key to use the service default.

With RF/TCN enabled, a requested screen checks fast clearances before they
reach the user. It sends high risk, low confidence, ambiguous labels and
provider failures to review. With RF/TCN skipped, usable pages go to review
by default. The separate `PPD_JEV_SHORT_CIRCUIT_LEGIT` option allows standalone
low-risk clears after validation. Confirmed threat intelligence keeps priority
and unusable crawl evidence yields `crawl_failed`.

Read category scores, confidence, model and status under `evidence_summary.jev`.
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
