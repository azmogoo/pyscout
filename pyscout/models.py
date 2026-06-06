from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse


@dataclass
class SubdomainResult:
    domain: str
    subdomains: list[str] = field(default_factory=list)
    sources: dict[str, int] = field(default_factory=dict)


@dataclass
class HTTPProbe:
    url: str
    status: int | None = None
    title: str = ""
    server: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    error: str = ""


@dataclass
class ScanReport:
    target: str
    subdomains: SubdomainResult | None = None
    probes: list[HTTPProbe] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "subdomains": {
                "domain": self.subdomains.domain,
                "count": len(self.subdomains.subdomains) if self.subdomains else 0,
                "hosts": self.subdomains.subdomains if self.subdomains else [],
            },
            "probes": [
                {
                    "url": p.url,
                    "status": p.status,
                    "title": p.title,
                    "server": p.server,
                    "error": p.error,
                }
                for p in self.probes
            ],
        }


def normalize_domain(raw: str) -> str:
    raw = raw.strip().lower()
    if raw.startswith("http"):
        raw = urlparse(raw).netloc or raw
    return raw.removeprefix("www.")
