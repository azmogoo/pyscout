# pyscout

Lightweight Python recon toolkit. Subdomain discovery via certificate transparency and wordlist brute-force, plus HTTP probing with JSON export.

## install

```bash
pip install -e .
```

## usage

```bash
# subdomain enumeration (crt.sh + wordlist)
pyscout subdomains example.com

# verify which hosts respond
pyscout subdomains example.com --verify

# probe a single url
pyscout probe --url https://example.com

# full scan — discover + probe top hosts
pyscout scan example.com --probe-limit 15 -o report.json
```

## commands

| command | description |
|---------|-------------|
| `subdomains` | enumerate hosts via crt.sh and built-in wordlist |
| `probe` | fetch status, title, and security headers |
| `scan` | combined discovery and probing |

## output

Text mode prints a summary to stdout. Use `-f json` or `-o report.json` for machine-readable output.

## notes

Only scan targets you are authorized to test. crt.sh queries are rate-limited — avoid aggressive automation.

## license

MIT
