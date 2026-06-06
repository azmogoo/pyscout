from __future__ import annotations

import logging
import re
from typing import Iterable

import httpx

from pyscout.models import SubdomainResult, normalize_domain

log = logging.getLogger(__name__)

DEFAULT_WORDLIST = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "beta", "app", "portal", "vpn", "cdn", "static", "assets",
    "blog", "shop", "store", "m", "mobile", "secure", "login",
    "dashboard", "internal", "git", "gitlab", "jenkins", "grafana",
]


async def fetch_crtsh(domain: str, client: httpx.AsyncClient) -> set[str]:
    """query certificate transparency logs via crt.sh."""
    url = "https://crt.sh/"
    params = {"q": f"%.{domain}", "output": "json"}
    try:
        resp = await client.get(url, params=params, timeout=30)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        log.warning("crt.sh lookup failed: %s", exc)
        return set()
    try:
        rows = resp.json()
    except ValueError:
        return set()
    hosts: set[str] = set()
    for row in rows:
        name = row.get("name_value", "")
        for part in name.split("\n"):
            part = part.strip().lower().removeprefix("*.")
            if part.endswith(domain) and "." in part:
                hosts.add(part)
    return hosts


def brute_candidates(domain: str, words: Iterable[str]) -> list[str]:
    return [f"{w}.{domain}" for w in words]


async def resolve_exists(hostname: str, client: httpx.AsyncClient) -> bool:
    """cheap existence check via https head request."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{hostname}"
        try:
            resp = await client.head(url, follow_redirects=True, timeout=8)
            if resp.status_code < 500:
                return True
        except httpx.HTTPError:
            continue
    return False


async def discover_subdomains(
    domain: str,
    wordlist: list[str] | None = None,
    use_crtsh: bool = True,
    brute: bool = True,
    verify: bool = False,
) -> SubdomainResult:
    domain = normalize_domain(domain)
    result = SubdomainResult(domain=domain)
    found: set[str] = set()

    async with httpx.AsyncClient(headers={"User-Agent": "pyscout/0.1"}) as client:
        if use_crtsh:
            crt_hosts = await fetch_crtsh(domain, client)
            found.update(crt_hosts)
            result.sources["crtsh"] = len(crt_hosts)

        if brute:
            words = wordlist or DEFAULT_WORDLIST
            candidates = brute_candidates(domain, words)
            live = 0
            for host in candidates:
                if verify:
                    if await resolve_exists(host, client):
                        found.add(host)
                        live += 1
                else:
                    found.add(host)
            result.sources["bruteforce"] = live if verify else len(candidates)

    result.subdomains = sorted(found)
    return result
