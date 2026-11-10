# Decisions

Choices made during the autonomous build where the brief left room. Each can be revisited.

| ID | Decision | Why |
|---|---|---|
| D-01 | **Dataclasses, not pydantic**, for `Finding` and config. | The brief allowed either; validation needs are small and this avoids a compiled dependency. |
| D-02 | **RFC 5737 documentation ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) are treated as public.** The blocked list is explicit instead of using Python's `is_private`, which includes them. | They are the required placeholders for "public" assets. They are not routable, so nothing real can be scanned through them. |
| D-03 | **A CIDR with host bits set (`203.0.113.5/27`) is rejected** rather than silently normalized. | The brief says to halt when the check is ambiguous. |
| D-04 | **Subdomains are not implied.** `example.org` in the whitelist does not cover `shop.example.org`. Wildcard entries (`*.example.org`) work only with `"allow_wildcard_entries": true`, and a target itself may never contain a wildcard. | Explicit lists are safer for authorization. |
| D-05 | **Internal targets go in a `local_only` section** of the whitelist. Private addresses and internal suffixes (`.local`, `.internal`, `.lan`, ...) are blocked from external providers even when listed in the public section. | Matches "may be scanned only by approved local tools". |
| D-06 | **Three conditions for a live call:** `--live` flag, `WEBSCAN_LIVE_MODE=true`, and provider approval. The brief required the last two; the flag was added so a leftover `.env` setting cannot make a routine run go live. | Defense in depth. |
| D-07 | **Parsers return `Issue` objects; normalization builds `Finding`s.** The brief's layout says "parser.py: raw output → Finding". | Keeps parsers pure and testable without config, and puts asset lookup and redaction in one place. |
| D-08 | **`scoring.json` and `providers.json` are optional** (built-in defaults, which approve no provider). `allowed_targets.json` and `assets_metadata.json` are mandatory outside the demo. | The two optional files hold no organization data; the mandatory ones are the authorization boundary. |
| D-09 | **Normalization divides by the maximum possible product** of the configured multipliers (45 by default). | Keeps 0–100 meaningful if the multipliers are tuned. |
| D-10 | **Band thresholds:** Critical 60, High 40, Medium 20, Low 5. | Chosen so a CVSS 9.0+ finding on a public, critical asset is Critical even without exploit evidence (score 60+), and typical missing-header findings are Low or Medium. Tune with the organization. |
| D-11 | **The KEV/exploit override also raises the score** to the High threshold, not just the label. | Otherwise a "High" could sort below a "Medium". |
| D-12 | **"Fix these 3 first" prefers batches containing a Critical or High finding.** Batches themselves are still ranked by total risk removed, as specified. | By total risk alone, "add a CSP header on four sites" outranked "fix the SQL injection on the donor portal". |
| D-13 | **Grade penalties:** Critical 15, High 5, Medium 1.5, Low 0.25. | With heavier penalties every realistic scan graded F, which is its own kind of alert fatigue. |
| D-14 | **Bundled KEV/EPSS snapshots are small curated subsets**, and the EPSS values are approximate. The demo always uses them; other commands prefer the refreshed full files. | Keeps the repo small and the demo repeatable. The KEV entries listed are real catalog members; the EPSS numbers are illustrative. |
| D-15 | **Quantro is file ingestion, not a per-target provider.** It implements `Provider`, but `scan` does not call it; `ingest-quantro` does. Findings for hosts outside `assets_metadata` are kept with conservative defaults. | The partner runs the scan; WebScan only reads the result. |
| D-16 | **`data/mock_results.json` is generated** from the mock sources by `scripts/build_mock_results.py`. `webscan demo` runs the real parsers on the raw mock files rather than loading it. | The demo then exercises the whole pipeline; the dataset is still available for `prioritize --input`. |
| D-17 | **WIP stubs are excluded from the default demo**; `--include-wip` adds their mock findings. | Keeps the default demo to features that are actually built. |
| D-18 | **Lookalike domain names and breached email aliases are never written to redacted output** (counts only). | They reveal the organization's domain and staff. |
| D-19 | **Local checks never follow redirects automatically** and authorize each request's host. | A redirect could otherwise lead to a host outside the approved inventory. |
| D-20 | **PDF engine order:** WeasyPrint → Playwright → locally installed Chrome/Chromium/Edge (headless) → HTML only. WeasyPrint is an optional extra. | WeasyPrint needs native libraries (Pango) that were not present on the build machine; headless Chrome was, and produced the PDF. Chrome is started with background networking disabled and loads only the local file. |
| D-21 | **Audit log stays redacted even with `--no-redact`.** | The flag is for local report output only. |
| D-22 | **CSV cells starting with `=`, `+`, `-`, `@` are prefixed with `'`.** | Scanner output is untrusted; this prevents spreadsheet formula injection. |
| D-23 | **Python 3.14 was used for the virtual environment** (the machine's default); the code targets 3.11+ syntax. | `python3.11` was not on the PATH. The full test suite was also run once on Python 3.11.9 and passed. |
| D-24 | **`ruff` line-length rule (E501) is ignored.** | Long strings in tests and tables read better unwrapped. |
| D-25 | **Later-phase scope:** built run history, change detection, and a read-only dashboard; left RBAC, scheduling, and clinic mode as 🚧. | Priority order in the brief. |
