# Browser extension integration

`phishingshield-persian` v3.4.1 always runs its offline URL Random Forest first.
Its optional backend connection is disabled by default and escalates only a
local `suspicious` result to this detector.

## Start the backend

Clone `phishing-detection-engine` and `agentic-phishing-review` as sibling
directories, copy `.env.example` to `.env`, set `OPENROUTER_API_KEY` and
`INTERNAL_REVIEW_API_KEY`, and optionally set `PPD_API_KEY`.

```bash
docker compose -f deploy/compose.yaml up -d --build --wait
curl --fail http://127.0.0.1:8088/ready
```

The readiness response must report `service_version: 3.1.0`, both RF and TCN
loaded, and the reviewer ready.

## Configure the extension

1. Open the Phishing Shield toolbar action or extension Options page.
2. Enable backend review.
3. Use `http://127.0.0.1:8088` for a local deployment. Remote origins must use
   HTTPS.
4. If `PPD_API_KEY` is configured, enter the same value in the extension.
5. Select **Test connection**, save, and reload existing tabs.

The request body is exactly:

```json
{"url": "https://site-under-review.example/path"}
```

No DOM, raw HTML, screenshot, cookies, request headers, form values, or script
bodies are sent by the extension. The detector performs its own safe crawl and
passes usable uncertain HTML to the reviewer only in memory.

## Failure behavior

- A confident local verdict does not call the backend.
- A detector HTTP/schema/timeout failure keeps the local result suspicious.
- `crawl_failed` is displayed as an inconclusive retrieval failure and is not
  converted into a phishing verdict.
- The detector calls the agent only after crawl quality gating and only for
  uncertain RF/TCN results.
