from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import datetime, timezone
from typing import Optional

from .types import DomainFacts
from .url_utils import hostname, registrable_domain, resolve_public_addresses


def _tls_days_remaining(host: str, address: str, timeout_s: float = 3.0) -> Optional[float]:
    context = ssl.create_default_context()
    with socket.create_connection((address, 443), timeout=timeout_s) as raw:
        with context.wrap_socket(raw, server_hostname=host) as secured:
            certificate = secured.getpeercert()
    not_after = certificate.get("notAfter")
    if not not_after:
        return None
    expires = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    return max((expires - datetime.now(timezone.utc)).total_seconds() / 86400.0, 0.0)


async def collect_domain_facts(url: str, allow_private: bool = False) -> DomainFacts:
    host = hostname(url)
    domain = registrable_domain(url)
    try:
        addresses = await asyncio.to_thread(resolve_public_addresses, url, allow_private)
        address_count: Optional[int] = len(addresses)
    except Exception:
        addresses = []
        address_count = None
    tls_days: Optional[float] = None
    if url.lower().startswith("https://") and addresses:
        for address in addresses:
            try:
                tls_days = await asyncio.wait_for(
                    asyncio.to_thread(_tls_days_remaining, host, address), timeout=4.0
                )
                break
            except Exception:
                continue
    return DomainFacts(
        registrable_domain=domain,
        dns_address_count=address_count,
        tls_days_remaining=tls_days,
        missing=address_count is None and tls_days is None,
    )
