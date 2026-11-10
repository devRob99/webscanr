# Google Safe Browsing / VirusTotal

**Status:** 🚧 WIP: disabled by default, returns mock data from `data/mock/reputation.json`

## What it adds
Detects when the organization's site is flagged as malicious, which is often the first visible sign of a compromise.

## What data it sends externally
The organization's public hostnames or URLs, plus the API key for each service.

## Environment variables
`GOOGLE_SAFE_BROWSING_API_KEY`, `VIRUSTOTAL_API_KEY` (either or both).

## Free vs paid
Both have free tiers with usage restrictions (Safe Browsing: non-commercial use; VirusTotal public API: low quota, no commercial use). **Verify current pricing and terms yourself before enabling; they change.**

## Rate limits
VirusTotal's public API is limited to a few requests per minute. Confirm both.

## Enabling it
Requires organization approval for this specific provider, then `"reputation"` in `approved_providers`
(or `enabled_providers` if nothing leaves the machine), `WEBSCAN_LIVE_MODE=true`, and `--live`.
Try the mock output with `webscan demo --include-wip`.

## Steps to finish wiring it
1. Verify both response shapes.
2. Read each service's terms for nonprofit use.
3. Consider the Safe Browsing Update API, which avoids sending URLs.
