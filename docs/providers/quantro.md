# Quantro

**Status:** 🚧 WIP: built against an **assumed** schema

## What it adds
Full web application vulnerability scan results from the organization's partner. This is also the main
source of findings for internal assets, which cannot go through HackerTarget.

## What data it sends externally
Nothing. WebScan reads a report file that Quantro delivered. It never contacts Quantro.

## Assumed schema
See `data/mock/quantro_report.json`. A JSON object with a `findings` list; each finding has:

| Field | Meaning | Maps to |
|---|---|---|
| `title` | Finding name | `vulnerability_name` |
| `cve` | CVE ID or null | `cve_id` |
| `cvss` | Numeric score | `base_severity` |
| `severity` | Label, used when `cvss` is not a number | `base_severity` via `severity_label_scores` |
| `host` | Hostname or IP | resolved to the asset alias |
| `url` | Where it was seen | `evidence` (redacted) |
| `description` | Scanner description | `description` |
| `exploit_available` | Boolean | `has_known_exploit` |
| `references` | List of links | `references` |

## Changing the mapping (no code changes)
Edit `quantro.field_mapping` in `config/providers.json`:

```json
{
  "findings_path": "scan.results",
  "fields": {"vulnerability_name": "name", "host": "target.hostname", "base_severity": "score.base"},
  "severity_label_scores": {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}
}
```

Paths are dotted and may include list indexes (`ids.cve.0`). `vulnerability_name` and `host` are required.

## Behavior
- Malformed records are skipped with a warning; the rest are ingested.
- Hosts missing from `assets_metadata.json` are kept, flagged, and given conservative defaults
  (public, criticality 2).
- Re-ingesting replaces earlier Quantro findings.

## Steps to finish wiring it
1. Obtain a **sanitized** real report from the organization.
2. If it is JSON, adjust the field mapping. If it is PDF, CSV, or XML, add a converter or a new parser
   function next to `parse_report`.
3. Replace the mock report with a sanitized sample that uses placeholder hosts, and update this page.
4. Ask Quantro whether their severity is CVSS or their own scale, and set `severity_label_scores`.
