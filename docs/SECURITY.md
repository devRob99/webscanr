# Security, authorization, and confidentiality

WebScan is a defensive tool for assessing systems the organization owns or is authorized to assess. These
rules are enforced in code where possible and are the team's responsibility where not.

## Authorization

1. **Whitelist first.** Every target is checked against `config/allowed_targets.json` before any network
   activity. The check lives in `scope/enforcer.py` and is called from the provider base class and again
   from the network guard.
2. **Fail-safe.** A missing, unreadable, malformed, or empty whitelist stops the command with
   `SCOPE HALT`. An out-of-scope target in the asset inventory stops the entire scan before anything runs.
3. **CIDR containment.** A range is in scope only if it is fully inside an allowed range. Partial overlap
   is rejected.
4. **Clean input only.** Targets must be a plain IP, CIDR, or hostname. Whitespace, shell metacharacters,
   URLs, embedded credentials, ports, wildcards, and non-ASCII characters are rejected. Targets are never
   passed to a shell; the only subprocess WebScan starts is a local browser for PDF export, with a fixed
   argument list.
5. **No private space to third parties.** RFC 1918, loopback, link-local, CGNAT, multicast, and reserved
   ranges, IPv6 equivalents, and internal hostname suffixes are refused for external providers even when
   whitelisted.

Limit: the enforcer does not resolve DNS. If a whitelisted public hostname resolves to a private address,
the hostname would still be sent. Keep the whitelist accurate.

## Live mode

Off by default. A live call requires all of:

- `--live` on the command line
- `WEBSCAN_LIVE_MODE=true` in `.env`
- third-party providers: listed in `approved_providers` in `config/providers.json`
- local checks: `local` listed in `enabled_providers`
- HackerTarget: an API key in `HACKERTARGET_API_KEY`

`webscan demo` never uses the network, whatever the settings. Blocked attempts are written to the audit log.

## What leaves the machine

| Action | Data sent | To |
|---|---|---|
| `webscan demo`, tests, default runs | nothing | – |
| `webscan refresh-reference-data` | nothing about the organization (two fixed public URLs are fetched) | cisa.gov, EPSS data host |
| HackerTarget (live, approved) | approved public hostname or IP, API key | api.hackertarget.com |
| Local checks (live) | ordinary web, TLS, and DNS requests | the approved target itself and the DNS resolver |
| Each WIP provider (live, approved) | see its page in `docs/providers/` | that provider |
| PDF export via headless browser | nothing (local file; background networking disabled) | – |

Scoring, batching, explanations, and reports are computed locally. No cloud AI service is used; the
optional LLM stub accepts only a `localhost` URL.

## Confidential data handling

- Real targets and asset details live only in `config/*.json`, which `.gitignore` excludes. Commit only
  `*.example.json` with placeholder data.
- `.env`, `output/`, and `logs/` are excluded from git.
- API keys are read from the environment, sent only to their own provider, and never logged.
- Console output, exports, reports, and logs pass through one redactor: known hostnames and IPs become
  asset aliases; other hostnames under the organization's domains, internal hostnames, IPs, email
  addresses, and common secret formats are masked.
- `--no-redact` writes to `output/unredacted/`, prints a warning, and is recorded in the audit log. The
  audit log itself is always redacted.
- Evidence never includes file contents, cookie values, or individual email addresses.

Before committing, check that nothing sensitive is staged:

```bash
git status --short
```

```bash
git ls-files config output logs .env
```

The second command should list only the four `config/*.example.json` files.

## Audit log

`logs/audit.jsonl`, one JSON object per line: timestamp, operator (`--operator` or OS user), command, event,
provider, targets (as aliases), live or mock, status, duration. It records every scan, provider run, API
call, scope rejection, blocked live attempt, report, and use of `--no-redact`. It is opened in append mode
and never rewritten by WebScan, but it is an ordinary file: protect it with file permissions if it must be
relied on as evidence.

## Responsible use of results

- Reports list weaknesses in the organization's systems. Treat them as confidential.
- Version-based findings are inferences. Confirm before acting, and before telling a vendor they are
  vulnerable.
- The plain-language text and framework mapping are aids, not professional advice or a certification.

## Reporting a problem with WebScan

Contact the project team: `[TBD]`.
