# Prebuilt image bundle

The image bundle is for 64-bit Linux (`linux/amd64`). It contains the detector, Chromium, RF/TCN artifacts, the agentic review service, and all Python dependencies. The target server needs only Docker Engine with Compose v2 and outbound network access; it does not need Python, Node.js, Chromium, a GPU, or a local model runtime.

Bundle files:

- `images.tar.gz` — both production images.
- `compose.yaml` — image-only hardened stack.
- `.env.example` — configuration template without secrets.
- `SHA256SUMS` — integrity hashes for every distributable file.

Deploy:

```bash
sha256sum -c SHA256SUMS
gzip -dc images.tar.gz | docker load
cp .env.example .env
# Set OPENROUTER_API_KEY and a long random INTERNAL_REVIEW_API_KEY in .env.
docker compose -f compose.yaml config --quiet
docker compose -f compose.yaml up -d --wait
curl --fail http://127.0.0.1:8088/ready
```

The UI is at `http://127.0.0.1:8090/` and the decision API is at `http://127.0.0.1:8088/`. Both are loopback-only by default. If a port is occupied, change `PPD_HOST_PORT` or `REVIEW_HOST_PORT` in `.env`.

Stop without deleting audit data:

```bash
docker compose -f compose.yaml down
```

Do not use `down -v` unless you intend to delete both SQLite volumes. Never copy a populated `.env` into the bundle.
