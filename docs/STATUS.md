# Status

## Pre-live checklist (for the team)

Nothing below has been done yet. Do not run a live scan until every box is ticked.

- [ ] Organization confirmed in writing that sending target data to HackerTarget is allowed under the NDA
- [ ] Organization approved each additional external provider individually
- [ ] Real `allowed_targets.json` and `assets_metadata.json` created locally and verified not tracked by git
- [ ] HackerTarget plan, quota, and rate limits confirmed; values set in config
- [ ] Sanitized sample of a real Quantro report obtained to replace the assumed schema
- [ ] License and repo visibility (public or private) confirmed with the organization

**License note:** there is deliberately no LICENSE file. The license, and whether this repository may be
public, must be confirmed with the organization first.

## What "tested" means here

Everything was built and tested against mock data and recorded fixtures only. **No live call has ever been
made** to HackerTarget, Quantro, or any target. Items marked 🟡 below have working code and passing tests
but have not been proven against the real service.

Legend: ✅ Done · 🟡 Partial · 🚧 WIP

## Required features

| Feature | Status | What is missing |
|---|---|---|
| Scope enforcer / input validation (5.1) | ✅ | Does not resolve DNS, so a whitelisted public hostname that points at a private IP is not detected. |
| HackerTarget client: rate limit, concurrency cap, persisted quota, backoff + jitter, text-error detection (5.2) | 🟡 | Tested with mocked HTTP and time only. Quota, limits, and error strings must be confirmed against the real account. |
| HackerTarget endpoints: Nmap, DNS lookup, reverse IP, subnet, host search, HTTP headers (5.2) | 🟡 | Paths follow public docs; response formats are assumed from documentation, not captured live. |
| HackerTarget OpenVAS and Nikto (5.2) | 🚧 | Mock data and parsers only. Live workflow (membership tier, likely submit-and-retrieve) not implemented; calling them live is refused. |
| Provider abstraction (5.2) | ✅ | – |
| Ingestion and normalization, dedup with `sources` (5.3) | ✅ | – |
| Quantro ingestion (5.3) | 🚧 | Built on an **assumed** JSON schema with a configurable field mapping. Needs a sanitized real report. JSON only. |
| `Finding` data contract with validation (5.4) | ✅ | – |
| Asset metadata, conservative defaults for unknown assets (5.5) | ✅ | – |
| Scoring engine, bands, exploitability override, explainable breakdown (5.6) | ✅ | Default thresholds are a starting point; tune with the organization. |
| KEV / EPSS enrichment from local snapshots + refresh command (5.6) | 🟡 | Bundled snapshots are small subsets and the EPSS values are approximate. The refresh command is tested with a fake download only; run it once to get real data. |
| Remediation batching (5.7) | ✅ | Remediation keys come from the knowledge catalog; findings it does not know batch only by identical name. |
| Terminal summary, JSON and CSV export (5.8) | ✅ | – |
| Redaction (5.9) | ✅ | Pattern-based; review a real report by hand before sharing it outside the organization. |
| Audit log (5.10) | ✅ | Append-only by convention (file opened in append mode); not tamper-proof. |
| Mock data and `webscan demo` (5.11) | ✅ | – |
| Tests and docs (5.12) | ✅ | 300+ tests, all offline. |

## Nonprofit differentiators

| Feature | Status | What is missing |
|---|---|---|
| Plain-language EN/ES knowledge base (6.1) | 🟡 | 47 finding types written. **Needs review** by a security-knowledgeable person and a fluent Spanish speaker before real use. |
| Platform-aware fix instructions (6.2) | 🟡 | Guidance by platform and finding group; platform menu names may change and should be spot-checked. |
| Executive summary, grade, "fix these 3 first" (6.3) | ✅ | – |
| Board-ready HTML report, both languages (6.4) | ✅ | – |
| PDF export (6.4) | 🟡 | WeasyPrint is optional and was **not** installed here (needs native libraries). PDF was produced through the headless-Chrome fallback. Without WeasyPrint, Playwright, or Chrome/Edge, only HTML is written. |
| CIS Controls v8 IG1 and NIST CSF 2.0 mapping (6.4) | 🟡 | Indicative mapping with paraphrased titles; verify against the official documents before using in a grant or insurance application. |

## Local passive checks (Section 7)

All run in the demo against fixtures. Live mode exists but is untested against real sites.

| Check | Status | What is missing |
|---|---|---|
| Security header audit | 🟡 | Live untested. |
| TLS: validity, expiry, HTTP→HTTPS redirect | 🟡 | Live untested. |
| TLS 1.0/1.1 support | 🟡 | Modern OpenSSL builds often cannot offer TLS 1.0/1.1, so the live probe may be inconclusive (then nothing is reported). |
| Cookie flags | 🟡 | Checks the home page only. |
| SPF / DMARC / DKIM | 🟡 | DKIM tries a short list of common selectors and can miss custom ones (reported with a caveat). |
| Donation page (HTTPS, processor, third-party scripts) | 🟡 | Only pages listed in `donation_paths`; scripts injected at runtime are not seen. |
| Donor privacy (trackers, privacy policy link) | 🟡 | Home page only; static HTML only. |
| Exposed files | 🟡 | Small fixed list of paths. |

## Third-party providers (Section 8): all 🚧 WIP, disabled by default

Each has mock data in `data/mock/<name>.json`, env vars in `.env.example`, and a doc in `docs/providers/`.
Live code is written from public documentation and has never been run.

| Provider | Status | What is missing |
|---|---|---|
| NVD CVE API (`nvd`) | 🚧 | Live verification, caching, rate limiting. Not yet wired into `prioritize`. |
| RDAP (`rdap`) | 🚧 | Live verification; registries without an expiration event. |
| GeoIP (`geoip`) | 🚧 | `geoip2` dependency and a real GeoLite2 database; ASN lookup. |
| Have I Been Pwned (`hibp`) | 🚧 | Paid key, domain verification with HIBP, live verification. |
| Shodan (`shodan`) | 🚧 | Key, live verification, more response fields. |
| Google Safe Browsing / VirusTotal (`reputation`) | 🚧 | Keys, live verification, terms-of-use check. |
| Lookalike domains (`lookalike`) | 🚧 | Live DNS verification, rate limiting, registration age. |
| Local LLM explanations (`local_llm`) | 🚧 | Verification with Ollama / LM Studio; not shown in reports yet. |

## Later phase (Section 9)

| Feature | Status | What is missing |
|---|---|---|
| Scan history (SQLite) and change detection (`webscan changes`) | 🟡 | Detects new, resolved, and worsened findings and writes a local alert file. No certificate/domain expiry trend, no email alerts. |
| Web dashboard (`webscan dashboard`) | 🟡 | Read-only overview, grade trend, report viewer with language toggle. Cannot start scans or edit config. |
| Role-based access control | 🚧 | Only bearer tokens mapped to role names; all roles see the same read-only pages. |
| Scheduled rescans | 🚧 | Not started (use cron / Task Scheduler with `webscan scan --all` for now). |
| External push alerts (ntfy.sh etc.) | 🚧 | Not started; would need organization approval and redacted content. |
| Multi-organization "clinic mode" | 🚧 | Not started. `--config-dir` plus `WEBSCAN_OUTPUT_DIR` per client is the manual workaround. |

## Known limitations

- Version-based findings (for example from an Nmap banner) are inferences; the evidence text says so.
- The redactor masks hostnames under the organization's known domains, internal suffixes, IPs, emails, and
  common secret formats. A sensitive name that fits none of those patterns would pass through.
- The header check on the HackerTarget side treats a response as HTTPS only if it saw a redirect to
  `https://` or an HSTS header.
