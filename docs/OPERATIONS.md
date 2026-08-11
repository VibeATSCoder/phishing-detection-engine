# Operations

## Integrated deployment

The supported stack has two non-root containers: `detector` is the decision API and `review` is the internal LangGraph/OpenRouter service. The detector passes its already-observed DOM to the reviewer, so the integrated review image omits Chromium. The standalone review project can still be built with Chromium for independent crawl mode.

```bash
cp .env.example .env
# Set OPENROUTER_API_KEY and a long random INTERNAL_REVIEW_API_KEY.
docker compose -f deploy/compose.yaml up -d --build
curl --fail http://127.0.0.1:8088/ready
python scripts/smoke_integrated.py
```

Both published ports bind to localhost by default. Put the detector behind TLS, authentication, request-size/rate limits, and an outbound policy appropriate for a crawler before exposing it. Do not expose the review container publicly unless its UI is intentionally required and protected.

`/health` reports local process/model state. `/ready` additionally requires the configured review service, so traffic is admitted only after RF, TCN, and the agent boundary are available. During an individual request, agent timeout, invalid output, or temporary unavailability fails closed to `suspicious`.

## Secrets and data

- Supply the OpenRouter key only as `OPENROUTER_API_KEY`; never bake it into an image or bundle.
- Use one long random `INTERNAL_REVIEW_API_KEY` for both `REVIEW_API_KEY` and `PPD_AGENT_API_KEY` through Compose.
- Optionally set `PPD_API_KEY` for the detector's `X-API-Key` check.
- Back up the `detector-data` and `review-data` named volumes. Neither contains raw HTML, screenshots, cookies, headers, or form values.
- Raw page/reference HTML is held only in job memory and is discarded after analysis.

## Monitoring

Track separately by stage and day:

- all four verdict rates and crawl-quality reasons;
- RF, TCN, ensemble, and OOD distributions;
- agent invocation, timeout, schema rejection, and disagreement rates;
- analyst/model disagreement and review turnaround;
- detector and agent latency p50/p95, queue depth, memory, and restarts;
- OpenRouter token use and error rate.

An increase in `crawl_failed` is a crawler/availability incident, not a phishing spike. An increase in `suspicious` with agent failures is a reviewer dependency incident, not evidence that sites became malicious.

## Contract and throughput checks

```bash
python scripts/check_agent.py --base-url http://127.0.0.1:8090 \
  --api-key "$INTERNAL_REVIEW_API_KEY" --iterations 2
python scripts/benchmark_api.py --urls test_urls.txt --concurrency 2
```

For an offline container smoke test, use the checked-in deterministic OpenRouter test double:

```bash
OPENROUTER_API_KEY=test INTERNAL_REVIEW_API_KEY=integration-secret \
docker compose -f deploy/compose.yaml -f deploy/compose.test.yaml up -d --build
python scripts/smoke_integrated.py
docker compose -f deploy/compose.yaml -f deploy/compose.test.yaml down -v
```

## Feed maintenance and rollback

Download feeds to a file first, archive the hash, then import. Do not convert exact-URL feeds into permanent domain-wide blocks.

```bash
python -m persianphish_detector download-feed --url FEED_URL --output feeds/feed.txt
python -m persianphish_detector ingest --format openphish --file feeds/feed.txt
```

Keep previous immutable images, model artifacts, and volume snapshots. Roll back by pinning the previous image tags and restoring compatible volumes. Never deploy an artifact whose release validator fails or whose feature order differs.
