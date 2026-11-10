# Shodan

**Status:** 🚧 WIP: disabled by default, returns mock data from `data/mock/shodan.json`

## What it adds
Open ports and possible vulnerabilities that Shodan has already observed on the organization's public IPs, without sending any new traffic to them.

## What data it sends externally
The organization's public IP addresses and the API key.

## Environment variables
`SHODAN_API_KEY`.

## Free vs paid
Host lookups need an account; some data needs a paid plan. **Verify current pricing and terms yourself before enabling; they change.**

## Rate limits
Roughly one request per second on most plans; confirm.

## Enabling it
Requires organization approval for this specific provider, then `"shodan"` in `approved_providers`
(or `enabled_providers` if nothing leaves the machine), `WEBSCAN_LIVE_MODE=true`, and `--live`.
Try the mock output with `webscan demo --include-wip`.

## Steps to finish wiring it
1. Verify the `/shodan/host/<ip>` response.
2. Add pacing.
3. Shodan's `vulns` are banner inferences; keep the caveat in the evidence text.
