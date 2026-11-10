"""Local passive checks. Each check takes a fetcher and returns provider-neutral Issues.

Nothing here is intrusive: every request is one a normal visitor's browser or a mail server
would make. Evidence never includes file contents, cookie values, or page text.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlsplit

from webscan.config import Asset
from webscan.models import Issue
from webscan.providers.local.fetch import Fetcher, HttpResponse
from webscan.providers.local.headers import analyze_headers

PAYMENT_PROCESSORS = {
    "stripe.com": "Stripe", "paypal.com": "PayPal", "paypalobjects.com": "PayPal", "donorbox.org": "Donorbox",
    "givebutter.com": "Givebutter", "classy.org": "Classy", "networkforgood.com": "Network for Good",
    "squareup.com": "Square", "square.site": "Square", "authorize.net": "Authorize.Net",
    "blackbaud.com": "Blackbaud", "givelively.org": "Give Lively", "zeffy.com": "Zeffy",
    "bloomerang.co": "Bloomerang", "kindful.com": "Kindful", "gofundme.com": "GoFundMe",
}
TRACKERS = {
    "google-analytics.com": "Google Analytics", "googletagmanager.com": "Google Tag Manager",
    "doubleclick.net": "Google Ads (DoubleClick)", "connect.facebook.net": "Meta (Facebook) Pixel",
    "facebook.com/tr": "Meta (Facebook) Pixel", "hotjar.com": "Hotjar", "clarity.ms": "Microsoft Clarity",
    "analytics.tiktok.com": "TikTok Pixel", "snap.licdn.com": "LinkedIn Insight", "ads-twitter.com": "X Ads",
    "fullstory.com": "FullStory", "mouseflow.com": "Mouseflow",
}


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.scripts: list[str] = []
        self.frames: list[str] = []
        self.forms: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None
        self._text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k: (v or "") for k, v in attrs}
        if tag == "script" and a.get("src"):
            self.scripts.append(a["src"])
        elif tag == "iframe" and a.get("src"):
            self.frames.append(a["src"])
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag == "a":
            self._href, self._text = a.get("href", ""), []

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag: str) -> None:
        if tag == "a" and self._href is not None:
            self.links.append((self._href, " ".join(self._text).strip()))
            self._href = None


def parse_page(body: str) -> _PageParser:
    parser = _PageParser()
    try:
        parser.feed(body or "")
    except Exception:  # noqa: BLE001, S110 - malformed HTML: keep whatever was parsed
        pass
    return parser


def _host_of(url: str, base: str) -> str:
    return (urlsplit(urljoin(base, url)).hostname or "").lower()


def _same_site(host: str, page_host: str) -> bool:
    site = ".".join(page_host.split(".")[-2:])
    return host == page_host or host.endswith("." + site) or host == site


def _match_vendor(url: str, table: dict[str, str]) -> str | None:
    lowered = url.lower()
    for needle, label in table.items():
        if needle in lowered:
            return label
    return None


def homepage(fetcher: Fetcher, host: str) -> HttpResponse | None:
    """The page a visitor lands on: HTTPS if it answers, otherwise HTTP. Follows one same-host hop."""
    for scheme in ("https", "http"):
        response = fetcher.get(f"{scheme}://{host}/")
        if response is None:
            continue
        location = response.headers.get("location", "")
        if 300 <= response.status < 400 and location:
            target = urljoin(response.url, location)
            if urlsplit(target).hostname == host:
                follow = fetcher.get(target)
                if follow is not None:
                    return follow
            if scheme == "https":
                return response
            continue
        return response
    return None


# ------------------------------------------------------------------ checks


def check_headers(fetcher: Fetcher, host: str, asset: Asset | None, cfg: dict[str, Any]) -> list[Issue]:
    page = homepage(fetcher, host)
    if page is None or 300 <= page.status < 400:
        return []
    return analyze_headers(page.headers, https=page.https)


def check_tls(fetcher: Fetcher, host: str, asset: Asset | None, cfg: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    info = fetcher.tls(host)
    if info is not None:
        warn_days = int(cfg.get("cert_expiry_warning_days", 30))
        if not info.valid:
            issues.append(
                Issue(name="TLS certificate is invalid or expired", knowledge_id="tls-cert-invalid",
                      evidence=f"Certificate validation failed: {info.error or 'unknown reason'}")
            )
        elif info.days_remaining is not None and info.days_remaining < 0:
            issues.append(
                Issue(name="TLS certificate has expired", knowledge_id="tls-cert-invalid",
                      evidence=f"Certificate expired {abs(info.days_remaining)} day(s) ago")
            )
        elif info.days_remaining is not None and info.days_remaining <= warn_days:
            issues.append(
                Issue(name=f"TLS certificate expires in {info.days_remaining} day(s)",
                      knowledge_id="tls-cert-expiring",
                      severity=7.0 if info.days_remaining <= 7 else None,
                      evidence=f"Certificate expires in {info.days_remaining} day(s) (warning threshold {warn_days})")
            )
        if info.legacy_protocols:
            issues.append(
                Issue(name="Deprecated TLS versions are still accepted", knowledge_id="tls-legacy-protocols",
                      evidence="Server accepted: " + ", ".join(info.legacy_protocols))
            )
    plain = fetcher.get(f"http://{host}/")
    if plain is not None:
        location = plain.headers.get("location", "").lower()
        if not (300 <= plain.status < 400 and location.startswith("https://")):
            issues.append(
                Issue(name="Site does not redirect to HTTPS", knowledge_id="no-https-redirect",
                      evidence=f"http:// request answered with HTTP {plain.status} and no redirect to https://")
            )
    return issues


def check_cookies(fetcher: Fetcher, host: str, asset: Asset | None, cfg: dict[str, Any]) -> list[Issue]:
    page = homepage(fetcher, host)
    if page is None or not page.set_cookies:
        return []
    problems: list[str] = []
    for raw in page.set_cookies:
        name = raw.split("=", 1)[0].strip()
        attrs = {part.strip().split("=", 1)[0].lower() for part in raw.split(";")[1:]}
        missing = [flag for flag, key in (("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite"))
                   if key not in attrs]
        if missing and re.fullmatch(r"[\w.-]{1,64}", name):
            problems.append(f"{name} (missing {', '.join(missing)})")
    if not problems:
        return []
    return [
        Issue(name="Cookies set without Secure, HttpOnly, or SameSite flags", knowledge_id="insecure-cookies",
              evidence="Cookies: " + "; ".join(sorted(problems)))
    ]


def check_email(fetcher: Fetcher, host: str, asset: Asset | None, cfg: dict[str, Any]) -> list[Issue]:
    """SPF, DMARC, and DKIM for the organization's email domain (runs once, on that domain)."""
    domain = (asset.email_domain or "").lower() if asset else ""
    if not domain or host.lower() != domain:
        return []
    issues: list[Issue] = []
    spf = fetcher.txt(domain, domain)
    if spf is not None:
        records = [r for r in spf if r.lower().startswith("v=spf1")]
        if not records:
            issues.append(Issue(name="No SPF record for the email domain", knowledge_id="missing-spf",
                                evidence="No TXT record starting with v=spf1"))
        elif any(r.split()[-1].lower() in ("+all", "all") for r in records):
            issues.append(Issue(name="SPF record allows any server to send email for the domain",
                                knowledge_id="missing-spf", evidence="SPF record ends in +all"))
    dmarc = fetcher.txt(f"_dmarc.{domain}", domain)
    if dmarc is not None:
        records = [r for r in dmarc if r.lower().replace(" ", "").startswith("v=dmarc1")]
        if not records:
            issues.append(Issue(name="No DMARC record: anyone can send email that appears to come from the domain",
                                knowledge_id="missing-dmarc", evidence="No DMARC TXT record found at _dmarc"))
        else:
            policy = re.search(r"\bp\s*=\s*(\w+)", records[0], re.IGNORECASE)
            if policy and policy.group(1).lower() == "none":
                issues.append(Issue(name="DMARC policy is set to monitor only (p=none)",
                                    knowledge_id="weak-dmarc-policy", evidence="DMARC record has p=none"))
    selectors = list(cfg.get("dkim_selectors", []))
    results = [fetcher.txt(f"{selector}._domainkey.{domain}", domain) for selector in selectors]
    if selectors and all(r is not None for r in results) and not any(results):
        issues.append(
            Issue(name="No DKIM key found under common selectors", knowledge_id="missing-dkim", severity=3.1,
                  evidence=f"Checked {len(selectors)} common selectors; none returned a key. "
                           "The mail provider may use a different selector, so confirm before acting.")
        )
    return issues


def check_donation(fetcher: Fetcher, host: str, asset: Asset | None, cfg: dict[str, Any]) -> list[Issue]:
    issues: list[Issue] = []
    for path in asset.donation_paths if asset else []:
        page = fetcher.get(f"https://{host}{path}")
        if page is None or page.status >= 400:
            page = fetcher.get(f"http://{host}{path}")
        if page is None or page.status >= 400:
            continue
        parsed = parse_page(page.body)
        insecure = []
        if not page.https:
            insecure.append("the donation page itself is served over http://")
        if any(urljoin(page.url, action).lower().startswith("http://") for action in parsed.forms):
            insecure.append("a form on the page submits to an http:// address")
        if insecure:
            issues.append(
                Issue(name="Donation page is not fully protected by HTTPS", knowledge_id="donation-form-insecure",
                      evidence=f"Path {path}: " + "; ".join(insecure))
            )
        resources = [*parsed.scripts, *parsed.frames, *(urljoin(page.url, a) for a in parsed.forms)]
        processors = sorted({p for p in (_match_vendor(r, PAYMENT_PROCESSORS) for r in resources) if p})
        third_party = sorted(
            {
                h for h in (_host_of(s, page.url) for s in parsed.scripts)
                if h and not _same_site(h, host) and not _match_vendor(h, PAYMENT_PROCESSORS)
            }
        )
        if third_party:
            processor_text = ", ".join(processors) if processors else "none detected"
            issues.append(
                Issue(name=f"{len(third_party)} third-party script source(s) load on the donation page",
                      knowledge_id="third-party-scripts-donation",
                      evidence=f"Path {path}. Payment processor: {processor_text}. "
                               f"Other script sources: {', '.join(third_party)}")
            )
    return issues


def check_privacy(fetcher: Fetcher, host: str, asset: Asset | None, cfg: dict[str, Any]) -> list[Issue]:
    page = homepage(fetcher, host)
    if page is None or page.status >= 300 or "html" not in page.headers.get("content-type", "html").lower():
        return []
    parsed = parse_page(page.body)
    issues: list[Issue] = []
    trackers = sorted({t for t in (_match_vendor(s, TRACKERS) for s in [*parsed.scripts, *parsed.frames]) if t})
    if trackers:
        issues.append(
            Issue(name=f"{len(trackers)} third-party tracker(s) found on the website",
                  knowledge_id="third-party-trackers", evidence="Trackers: " + ", ".join(trackers))
        )
    has_policy = any(
        re.search(r"privacy|privacidad", f"{href} {text}", re.IGNORECASE) for href, text in parsed.links
    )
    if not has_policy:
        issues.append(
            Issue(name="No privacy policy link found on the home page", knowledge_id="missing-privacy-policy",
                  evidence="No link whose address or text mentions a privacy policy")
        )
    return issues


_EXPOSED_SIGNATURES: list[tuple[str, str, str, Callable[[HttpResponse], bool]]] = [
    (r"\.git/", "exposed-git", "Exposed .git repository",
     lambda r: r.body.lstrip().startswith("ref:") or bool(re.fullmatch(r"[0-9a-f]{40}\s*", r.body))),
    (r"\.env$", "exposed-env", "Exposed .env configuration file",
     lambda r: bool(re.search(r"^[A-Z][A-Z0-9_]{2,}\s*=", r.body, re.MULTILINE))),
    (r".", "exposed-backup", "Backup file exposed on the web server",
     lambda r: "html" not in r.headers.get("content-type", "").lower() and len(r.body) > 0),
]


def check_exposed_files(fetcher: Fetcher, host: str, asset: Asset | None, cfg: dict[str, Any]) -> list[Issue]:
    """A few single GET requests for commonly exposed files, compared with a baseline 404."""
    base = None
    for scheme in ("https", "http"):
        probe = fetcher.get(f"{scheme}://{host}/")
        if probe is not None and not (scheme == "http" and probe.headers.get("location", "").startswith("https://")):
            base = f"{scheme}://{host}"
            break
    if base is None:
        return []
    baseline = fetcher.get(f"{base}/webscan-baseline-check-that-should-not-exist")
    issues: list[Issue] = []
    for path in cfg.get("exposed_paths", []):
        response = fetcher.get(f"{base}{path}")
        if response is None or response.status != 200:
            continue
        if baseline is not None and baseline.status == 200 and baseline.body == response.body:
            continue  # the server answers 200 for everything ("soft 404"): not a real file
        for pattern, knowledge_id, name, looks_real in _EXPOSED_SIGNATURES:
            if re.search(pattern, path):
                if looks_real(response):
                    issues.append(
                        Issue(name=name, knowledge_id=knowledge_id,
                              evidence=f"GET {path} returned HTTP 200 ({len(response.body)} bytes). "
                                       "Contents were not stored.")
                    )
                break
    return issues


CHECKS: dict[str, Callable[[Fetcher, str, Asset | None, dict[str, Any]], list[Issue]]] = {
    "headers": check_headers,
    "tls": check_tls,
    "cookies": check_cookies,
    "email": check_email,
    "donation": check_donation,
    "privacy": check_privacy,
    "exposed_files": check_exposed_files,
}
