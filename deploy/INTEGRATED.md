# Minimal integrated deployment

Compatibility set: detector **v3.8.0**, reviewer **v1.11.0**, optional extension client **v3.6.0**. The exact contract is recorded in `COMPATIBILITY.json`.

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

To connect `phishingshield-persian` v3.8.0, open the extension's Options page,
enable backend review, use `http://127.0.0.1:8088`, and enter the same
`PPD_API_KEY` configured here. The extension sends only suspicious URLs and
never sends page HTML, cookies, headers, or form values.

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
