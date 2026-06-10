from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys

from pyscout.http_probe import probe_hosts, probe_url
from pyscout.models import ScanReport, normalize_domain
from pyscout.report import print_report, write_json
from pyscout.subdomains import discover_subdomains


def setup_logging(verbose: bool) -> None:
    logging.basicConfig(level=logging.DEBUG if verbose else logging.WARNING)


async def cmd_subdomains(args: argparse.Namespace) -> int:
    result = await discover_subdomains(
        args.domain,
        use_crtsh=not args.no_crtsh,
        brute=not args.no_brute,
        verify=args.verify,
    )
    report = ScanReport(target=args.domain, subdomains=result)
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_report(report)
    if args.output:
        write_json(report, args.output)
    return 0


async def cmd_probe(args: argparse.Namespace) -> int:
    if args.url:
        probe = await probe_url(args.url)
        probes = [probe]
    else:
        hosts = args.hosts or [normalize_domain(args.domain)]
        probes = await probe_hosts(hosts, scheme=args.scheme)
    report = ScanReport(target=args.url or args.domain, probes=probes)
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_report(report)
    return 0


async def cmd_scan(args: argparse.Namespace) -> int:
    domain = normalize_domain(args.domain)
    subs = await discover_subdomains(domain, verify=args.verify)
    hosts = subs.subdomains[: args.probe_limit]
    probes = await probe_hosts(hosts) if hosts else []
    report = ScanReport(target=domain, subdomains=subs, probes=probes)
    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        print_report(report)
    if args.output:
        write_json(report, args.output)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="pyscout", description="lightweight recon toolkit")
    parser.add_argument("-v", "--verbose", action="store_true")
    sub = parser.add_subparsers(dest="command", required=True)

    sd = sub.add_parser("subdomains", help="discover subdomains")
    sd.add_argument("domain")
    sd.add_argument("--no-crtsh", action="store_true")
    sd.add_argument("--no-brute", action="store_true")
    sd.add_argument("--verify", action="store_true", help="confirm hosts respond to http")
    sd.add_argument("-f", "--format", choices=["text", "json"], default="text")
    sd.add_argument("-o", "--output", default="")

    pr = sub.add_parser("probe", help="probe http endpoints")
    pr.add_argument("--url", default="")
    pr.add_argument("--domain", default="")
    pr.add_argument("--hosts", nargs="*", default=None)
    pr.add_argument("--scheme", default="https")
    pr.add_argument("-f", "--format", choices=["text", "json"], default="text")

    sc = sub.add_parser("scan", help="subdomain discovery + http probe")
    sc.add_argument("domain")
    sc.add_argument("--verify", action="store_true")
    sc.add_argument("--probe-limit", type=int, default=10)
    sc.add_argument("-f", "--format", choices=["text", "json"], default="text")
    sc.add_argument("-o", "--output", default="")

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    setup_logging(args.verbose)
    commands = {
        "subdomains": cmd_subdomains,
        "probe": cmd_probe,
        "scan": cmd_scan,
    }
    raise SystemExit(asyncio.run(commands[args.command](args)))


if __name__ == "__main__":
    main()
