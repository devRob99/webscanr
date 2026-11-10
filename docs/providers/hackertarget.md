# HackerTarget

**Status:** 🟡 client and core endpoints built, tested with mocks only · 🚧 OpenVAS and Nikto

## What it adds
Hosted Nmap port scans, HTTP header retrieval, DNS lookup, host search, reverse IP lookup, and subnet
calculation, without running a scanner engine locally.

## What data it sends externally
The approved **public** hostname or IP (query parameter `q`) and the API key (`apikey`). Private and
internal targets are refused before the request is built.

## Environment and config
- `HACKERTARGET_API_KEY` in `.env`. Without it the provider stays on mock data.
- `WEBSCAN_LIVE_MODE=true`, `--live`, and `"hackertarget"` in `approved_providers`.
- `config/providers.json` → `hackertarget`: `base_url`, `endpoints`, `min_delay_seconds`,
  `max_concurrent`, `daily_quota`, `timeout_seconds`, `max_retries`, `backoff_base_seconds`,
  `backoff_max_seconds`.

## Endpoints
| Key | Path | Targets | Status |
|---|---|---|---|
| `nmap` | `/nmap/` | hostname, IP | 🟡 |
| `httpheaders` | `/httpheaders/` | hostname, IP | 🟡 |
| `dnslookup` | `/dnslookup/` | hostname | 🟡 |
| `hostsearch` | `/hostsearch/` | hostname | 🟡 |
| `reverseiplookup` | `/reverseiplookup/` | IP | 🟡 |
| `subnetcalc` | `/subnetcalc/` | CIDR | 🟡 (context only, no findings) |
| `nikto` | placeholder | hostname, IP | 🚧 mock only |
| `openvas` | placeholder | hostname, IP | 🚧 mock only |

When an asset has hostnames, its IPs only run IP-specific endpoints, so the same host is not scanned twice.

## Rate limits and quota
Defaults are conservative guesses: 2 seconds between requests, 1 concurrent request, 50 requests per day.
**Verify the real limits for the organization's plan** (free and membership tiers differ) and set them in
`providers.json`. The daily counter is stored in `output/state/hackertarget_quota.json` and survives
restarts. Every attempt, including retries, counts.

HTTP 429, 5xx, timeouts, and connection errors are retried with exponential backoff and jitter
(`Retry-After` is honored). HackerTarget also reports some errors as plain text with HTTP 200
(for example an exceeded API count); those are detected and never parsed as results.

## Free vs paid
Some tools (OpenVAS, Nikto, higher quotas) require a membership. Check current pricing and terms on
HackerTarget's site; do not rely on numbers in this repository.

## Steps to finish wiring it
1. Tick the pre-live checklist in `docs/STATUS.md` (NDA confirmation first).
2. Confirm endpoint paths and response formats against HackerTarget's API documentation.
3. Run one approved, low-impact lookup (for example `dnslookup`) and compare the raw output with
   `data/mock/hackertarget/`. Adjust `parser.py` if formats differ.
4. Confirm the plain-text error strings in `client.py` (`_TEXT_ERRORS`).
5. For OpenVAS and Nikto: find out how results are requested and retrieved on the organization's plan,
   then implement that workflow in `client.py` and remove `wip=True` in `endpoints.py`.
