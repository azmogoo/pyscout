from __future__ import annotations

import json
from typing import Any

from pyscout.models import HTTPProbe, ScanReport, SubdomainResult


def print_report(report: ScanReport) -> None:
    print(f"target: {report.target}\n")
    if report.subdomains:
        print(f"subdomains ({len(report.subdomains.subdomains)}):")
        for host in report.subdomains.subdomains[:50]:
            print(f"  {host}")
        if len(report.subdomains.subdomains) > 50:
            print(f"  ... and {len(report.subdomains.subdomains) - 50} more")
        if report.subdomains.sources:
            print(f"  sources: {report.subdomains.sources}")
        print()
    if report.probes:
        print("http probes:")
        for p in report.probes:
            if p.error:
                print(f"  {p.url}  error: {p.error}")
            else:
                print(f"  [{p.status}] {p.url}  {p.title or p.server}")


def write_json(report: ScanReport, path: str) -> None:
    with open(path, "w") as f:
        json.dump(report.to_dict(), f, indent=2)
