# NVD CVE API

**Status:** 🚧 WIP: disabled by default, returns mock data from `data/mock/nvd.json`

## What it adds
CVE descriptions, CVSS vectors, and reference links for findings that have a CVE ID.

## What data it sends externally
CVE identifiers only. No hostnames, IPs, or findings.

## Environment variables
`NVD_API_KEY` (optional).

## Free vs paid
Free. An API key is free on request and raises the rate limit. **Verify current pricing and terms yourself before enabling; they change.**

## Rate limits
Public documentation describes a low unauthenticated limit and a higher one with a key. Confirm the current numbers.

## Enabling it
Requires organization approval for this specific provider, then `"nvd"` in `approved_providers`
(or `enabled_providers` if nothing leaves the machine), `WEBSCAN_LIVE_MODE=true`, and `--live`.
Try the mock output with `webscan demo --include-wip`.

## Steps to finish wiring it
1. Verify `NvdProvider.parse_response` against a live response.
2. Cache results under `data/reference/` so each CVE is fetched once.
3. Add request pacing.
4. Call `enrich()` from `pipeline.prioritize` when the provider is approved.
