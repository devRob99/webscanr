# Have I Been Pwned

**Status:** 🚧 WIP: disabled by default, returns mock data from `data/mock/hibp.json`

## What it adds
Whether staff email addresses at the organization's domain appear in known data breaches. Only counts and breach names are reported.

## What data it sends externally
The organization's email domain.

## Environment variables
`HIBP_API_KEY`.

## Free vs paid
The domain search API needs a paid subscription, and the domain must be verified with HIBP first. **Verify current pricing and terms yourself before enabling; they change.**

## Rate limits
Depends on the subscription tier.

## Enabling it
Requires organization approval for this specific provider, then `"hibp"` in `approved_providers`
(or `enabled_providers` if nothing leaves the machine), `WEBSCAN_LIVE_MODE=true`, and `--live`.
Try the mock output with `webscan demo --include-wip`.

## Steps to finish wiring it
1. Verify the domain with HIBP.
2. Verify the `breacheddomain` response shape and the 404 (no breaches) case.
3. Decide with the organization who may see the per-person detail; WebScan deliberately does not store it.
