# RDAP (domain registration)

**Status:** 🚧 WIP: disabled by default, returns mock data from `data/mock/rdap.json`

## What it adds
Warns when the organization's domain name is within 60 days of expiring.

## What data it sends externally
The organization's domain name.

## Environment variables
None.

## Free vs paid
Free; RDAP is a public protocol. **Verify current pricing and terms yourself before enabling; they change.**

## Rate limits
Each registry sets its own. One lookup per domain per day is plenty.

## Enabling it
Requires organization approval for this specific provider, then `"rdap"` in `approved_providers`
(or `enabled_providers` if nothing leaves the machine), `WEBSCAN_LIVE_MODE=true`, and `--live`.
Try the mock output with `webscan demo --include-wip`.

## Steps to finish wiring it
1. Verify the response from `https://rdap.org/domain/<domain>` for the organization's TLD.
2. Handle registries that omit the expiration event.
3. Cache the result.
