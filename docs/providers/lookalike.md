# Lookalike domain check

**Status:** 🚧 WIP: disabled by default, returns mock data from `data/mock/lookalike.json`

## What it adds
Generates typo and look-alike variants of the organization's domain on this machine and reports how many are registered (possible fake donation sites).

## What data it sends externally
DNS queries for the generated variants go to the configured DNS resolver, which reveals near-copies of the organization's domain. That is why approval is required.

## Environment variables
None. `stubs.lookalike_max_variants` in `providers.json` caps the number of lookups.

## Free vs paid
Free. **Verify current pricing and terms yourself before enabling; they change.**

## Rate limits
Self-imposed: the variant cap. Add pacing before live use.

## Enabling it
Requires organization approval for this specific provider, then `"lookalike"` in `approved_providers`
(or `enabled_providers` if nothing leaves the machine), `WEBSCAN_LIVE_MODE=true`, and `--live`.
Try the mock output with `webscan demo --include-wip`.

## Steps to finish wiring it
1. Verify live DNS resolution and add pacing.
2. Add registration age via RDAP for each hit.
3. Consider certificate transparency logs as a passive alternative.
4. Names are shown only with `--no-redact`; decide where the full list should be delivered.
