# WebScan Roadmap

Capstone: Angelo State University Senior Design Project with Cyber Ready Clinic, fall 2026.
Final demo: early December 2026 (exact date `[TBD]`).

| Role | Name |
|---|---|
| Team members | `[TBD]` |
| Faculty advisor | `[TBD]` |
| Organization contact | `[TBD]` |

**Priority order if time runs short:** Phases 1–4 (minimum demo) → 5–6 → 7–9 → 10 (optional).

Current state of every feature lives in [STATUS.md](STATUS.md). This file is the plan.

## Phases

| # | Phase | Deliverables | Depends on | Owner | Target date |
|---|---|---|---|---|---|
| 1 | Foundation | Repo layout, `pyproject.toml`, `.gitignore`, `.env.example`, config loading + validation, `Finding` dataclass, redaction, audit logger, example configs | – | `[TBD]` | `[TBD]` |
| 2 | Scope enforcer | Target parsing (IP / CIDR / domain), whitelist check, fail-safe halts, private-address blocking, injection rejection, full tests | 1 | `[TBD]` | `[TBD]` |
| 3 | Mock data, parsers, normalization | Mock HackerTarget payloads in their raw formats, assumed Quantro schema + field mapping, parsers, dedup with `sources` | 1, 2 | `[TBD]` | `[TBD]` |
| 4 | Scoring, enrichment, batching — **minimum demo** | Risk formula, bands, exploitability override, KEV/EPSS snapshots + refresh script, remediation batching, `webscan demo` with terminal + JSON/CSV | 3 | `[TBD]` | `[TBD]` |
| 5 | HackerTarget client | Rate limit, concurrency cap, persisted daily quota, backoff + jitter, plain-text error detection, live-mode gating, provider abstraction | 2, 3 | `[TBD]` | `[TBD]` |
| 6 | Nonprofit differentiators | EN/ES knowledge base, platform-aware fixes, grade, "fix these 3 first", HTML/PDF report, CIS IG1 + NIST CSF mapping | 4 | `[TBD]` | `[TBD]` |
| 7 | Local passive checks | Headers, TLS, cookies, SPF/DMARC/DKIM, donation page, donor privacy, exposed files | 2, 5 | `[TBD]` | `[TBD]` |
| 8 | WIP third-party providers | NVD, RDAP, GeoIP, HIBP, Shodan, Safe Browsing/VirusTotal, lookalike domains, local LLM — stubs with mock data and docs | 5 | `[TBD]` | `[TBD]` |
| 9 | Docs pass | README, architecture diagram, STATUS, provider docs, SECURITY, DECISIONS | all | `[TBD]` | `[TBD]` |
| 10 | Optional later phase | Dashboard, RBAC, scheduled rescans + change detection, clinic mode | 4, 6 | `[TBD]` | `[TBD]` |

## Deliverables per phase

### Phase 1 — Foundation
- `src/webscan/config.py`, `models.py`, `sanitize/redact.py`, `audit/logger.py`
- `config/*.example.json` with placeholder data only

### Phase 2 — Scope enforcer
- `src/webscan/scope/enforcer.py`, one enforcement point called by the provider base class
- Tests: valid, invalid, out of scope, partial CIDR overlap, private addresses, injection, missing whitelist

### Phase 3 — Mock data, parsers, normalization
- `data/mock/hackertarget/**`, `data/mock/quantro_report.json`, `data/mock_results.json`
- `providers/hackertarget/parser.py`, `providers/quantro/parser.py`, `ingest/normalize.py`

### Phase 4 — Scoring, enrichment, batching (minimum demo)
- `scoring/engine.py`, `enrichment/kev.py`, `enrichment/epss.py`, `batching/engine.py`
- `reporting/terminal.py`, `reporting/export.py`, `webscan demo`

### Phase 5 — HackerTarget client
- `providers/hackertarget/client.py` and `endpoints.py`, `providers/base.py`, `providers/guard.py`
- OpenVAS and Nikto endpoints stay 🚧 until verified against the account's membership tier

### Phase 6 — Nonprofit differentiators
- `knowledge/en.json`, `knowledge/es.json`, `knowledge/catalog.json`, `knowledge/frameworks.json`
- `summary.py` (grade + executive summary), `reporting/html_report.py` + template, PDF export

### Phase 7 — Local passive checks
- `providers/local/*` with a fixture fetcher (demo) and a live fetcher (gated)

### Phase 8 — WIP third-party providers
- `providers/stubs/*`, `data/mock/stubs/*`, `docs/providers/*`

### Phase 9 — Docs pass
- `README.md`, `docs/ARCHITECTURE.md`, `docs/STATUS.md`, `docs/DECISIONS.md`, `docs/SECURITY.md`

### Phase 10 — Optional later phase
- Scan history (SQLite), change detection, read-only dashboard
- RBAC, scheduled rescans, clinic mode

## Risks

| Risk | Impact | Mitigation |
|---|---|---|
| Organization has not confirmed that sending target data to HackerTarget is allowed under the NDA | Live scanning blocked | Everything runs on mock data by default; live mode needs `.env` flag **and** provider approval in config |
| Quantro report format is unknown | Ingestion may not match the real export | Parser is driven by a field-mapping config; replace the assumed schema once a sanitized sample arrives |
| HackerTarget OpenVAS / Nikto need a membership tier with a different workflow | Those scan types unavailable live | Built as WIP endpoints with mock data; verify against account and docs |
| HackerTarget free-tier quota is small | Scans of the whole inventory may not fit in one day | Persisted daily quota counter, configurable endpoint list, queue with backoff |
| Real targets or keys accidentally committed | NDA breach | `.gitignore` for `config/*.json`, `.env`, `output/`, `logs/`; only `*.example.json` tracked; redaction on by default |
| PDF library (WeasyPrint) needs native libraries | PDF export fails on some machines | Fallback chain: WeasyPrint → Playwright → headless Chrome → HTML only |
| KEV / EPSS snapshots go stale | Exploitability scoring out of date | `webscan refresh-reference-data` downloads public files (sends no target data) |
| Plain-language text or Spanish translation is inaccurate | Misleading advice for non-technical readers | Have a fluent reviewer and the faculty advisor review `knowledge/*.json` before the final demo |
| License and repo visibility undecided | Cannot publish | No LICENSE file until the organization confirms |
