from __future__ import annotations

import logging
import re

import httpx

from pyscout.models import HTTPProbe

log = logging.getLogger(__name__)

TITLE_RE = re.compile(r"<title[^>]*>([^<]+)</title>", re.IGNORECASE)


async def probe_url(url: str, client: httpx.AsyncClient | None = None) -> HTTPProbe:
    own_client = client is None
    if own_client:
        client = httpx.AsyncClient(
            follow_redirects=True,
            timeout=12,
            headers={"User-Agent": "pyscout/0.1"},
        )
    probe = HTTPProbe(url=url)
    try:
        resp = await client.get(url)
        probe.status = resp.status_code
        probe.server = resp.headers.get("server", "")
        probe.headers = {
            k.lower(): v
            for k, v in resp.headers.items()
            if k.lower() in ("server", "x-powered-by", "content-type", "strict-transport-security")
        }
        match = TITLE_RE.search(resp.text[:8192])
        if match:
            probe.title = match.group(1).strip()[:120]
    except httpx.HTTPError as exc:
        probe.error = str(exc)
    finally:
        if own_client:
            await client.aclose()
    return probe


async def probe_hosts(hosts: list[str], scheme: str = "https") -> list[HTTPProbe]:
    urls = [f"{scheme}://{h}" for h in hosts]
    async with httpx.AsyncClient(
        follow_redirects=True,
        timeout=12,
        headers={"User-Agent": "pyscout/0.1"},
    ) as client:
        import asyncio

        return list(await asyncio.gather(*(probe_url(u, client) for u in urls)))
