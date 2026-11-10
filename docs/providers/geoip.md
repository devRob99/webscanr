# GeoIP

**Status:** 🚧 WIP: disabled by default, returns mock data from `data/mock/geoip.json`

## What it adds
Country and network owner for each public IP, as an informational note.

## What data it sends externally
Nothing. It reads a local MaxMind GeoLite2 database.

## Environment variables
`GEOIP_DB_PATH` (path to the `.mmdb` file).

## Free vs paid
GeoLite2 is free with a MaxMind account and licence agreement. **Verify current pricing and terms yourself before enabling; they change.**

## Rate limits
None (local file).

## Enabling it
Requires organization approval for this specific provider, then `"geoip"` in `approved_providers`
(or `enabled_providers` if nothing leaves the machine), `WEBSCAN_LIVE_MODE=true`, and `--live`.
Try the mock output with `webscan demo --include-wip`.

## Steps to finish wiring it
1. Add the `geoip2` package as an optional dependency.
2. Download GeoLite2-City and GeoLite2-ASN and set `GEOIP_DB_PATH` (the files are ignored by git).
3. Verify field names and add the ASN lookup.
4. Add `"geoip"` to `enabled_providers`.
