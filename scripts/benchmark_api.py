from __future__ import annotations

import argparse
import asyncio
import statistics
import time
from pathlib import Path

import httpx


async def run(base_url: str, urls: list[str], concurrency: int, api_key: str = "") -> None:
    semaphore = asyncio.Semaphore(concurrency)
    latencies: list[float] = []
    verdicts: dict[str, int] = {}

    headers = {"x-api-key": api_key} if api_key else {}
    async with httpx.AsyncClient(timeout=40, trust_env=False, headers=headers) as client:
        async def detect(url: str) -> None:
            async with semaphore:
                started = time.perf_counter()
                response = await client.post(base_url.rstrip("/") + "/v1/detect", json={"url": url})
                response.raise_for_status()
                payload = response.json()
                latencies.append((time.perf_counter() - started) * 1000)
                verdict = str(payload.get("verdict", "unknown"))
                verdicts[verdict] = verdicts.get(verdict, 0) + 1

        started = time.perf_counter()
        await asyncio.gather(*(detect(url) for url in urls))
        elapsed = time.perf_counter() - started
    ordered = sorted(latencies)
    p95 = ordered[min(len(ordered) - 1, int(len(ordered) * 0.95))]
    print({
        "requests": len(urls),
        "concurrency": concurrency,
        "elapsed_s": round(elapsed, 3),
        "requests_per_second": round(len(urls) / elapsed, 3),
        "latency_mean_ms": round(statistics.mean(latencies), 3),
        "latency_p95_ms": round(p95, 3),
        "verdicts": verdicts,
    })


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8088")
    parser.add_argument("--urls", required=True, help="UTF-8 file containing one URL per line")
    parser.add_argument("--concurrency", type=int, default=2)
    parser.add_argument("--api-key", default="")
    args = parser.parse_args()
    urls = [line.strip() for line in Path(args.urls).read_text(encoding="utf-8").splitlines() if line.strip()]
    if not urls:
        raise SystemExit("URL file is empty")
    asyncio.run(run(args.base_url, urls, max(1, args.concurrency), args.api_key))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
