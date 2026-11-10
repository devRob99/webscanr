"""Generate the mock HTTP/TLS/DNS fixtures used by the local passive checks in demo mode.

Placeholder data only. Run: python scripts/build_local_fixtures.py
"""

import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "data" / "mock" / "local"
HTML = {"Content-Type": "text/html; charset=UTF-8"}

donate_home = """<!doctype html><html><head><title>Donate</title>
<meta name="generator" content="WordPress 6.4">
<script src="/wp-includes/js/jquery/jquery.js?ver=1.12.4"></script>
</head><body><a href="/donate/">Give today</a> <a href="/privacy-policy/">Privacy Policy</a></body></html>"""
donate_page = """<!doctype html><html><head><title>Give today</title>
<script src="/wp-includes/js/jquery/jquery.js?ver=1.12.4"></script>
<script src="https://js.stripe.com/v3/"></script>
<script src="https://www.googletagmanager.com/gtag/js?id=G-PLACEHOLDER"></script>
<script src="https://connect.facebook.net/en_US/fbevents.js"></script>
<script src="https://cdn.example.net/widgets/chat.js"></script>
</head><body><form action="https://donate.example.org/donate/submit" method="post">
<input name="amount"><button>Donate</button></form>
<a href="/privacy-policy/">Privacy Policy</a></body></html>"""
donate_headers = {**HTML, "Server": "nginx", "X-Powered-By": "PHP/7.4.33", "X-Content-Type-Options": "nosniff",
                  "Link": '<https://donate.example.org/wp-json/>; rel="https://api.w.org/"'}

www_home = """<!doctype html><html><head><title>Example Community Nonprofit</title>
<script src="https://static.parastorage.com/services/wix-thunderbolt/dist/main.js"></script>
<script src="https://www.googletagmanager.com/gtag/js?id=G-PLACEHOLDER"></script>
<script src="https://static.hotjar.com/c/hotjar-000000.js"></script>
</head><body><a href="/about">About us</a> <a href="/privacy">Privacy</a></body></html>"""

archive_home = """<!doctype html><html><head><title>Spring Campaign 2019</title>
<script src="/js/jquery-1.12.4.min.js"></script></head>
<body><h1>Thank you for a great campaign</h1><a href="/files/">Downloads</a></body></html>"""

staging_home = """<!doctype html><html><head><title>STAGING</title></head>
<body><p>Staging copy. Not for public use.</p></body></html>"""

fixtures = {
    "donate.example.org": {
        "http": {
            "http://donate.example.org/": {"status": 301, "headers": {"Location": "https://donate.example.org/"}},
            "https://donate.example.org/": {
                "status": 200, "headers": donate_headers, "body": donate_home,
                "set_cookies": ["wp_donor_session=placeholder; path=/", "wp_lang=en; path=/; Secure; SameSite=Lax"],
            },
            "https://donate.example.org/donate/": {"status": 200, "headers": donate_headers, "body": donate_page},
        },
        "not_found": {"status": 404, "headers": HTML, "body": "<html><body>Page not found</body></html>"},
        "tls": {"valid": True, "days_remaining": 12, "legacy_protocols": ["TLS 1.0", "TLS 1.1"]},
    },
    "www.example.org": {
        "http": {
            "http://www.example.org/": {"status": 301, "headers": {"Location": "https://www.example.org/"}},
            "https://www.example.org/": {
                "status": 200,
                "headers": {**HTML, "Server": "Pepyaka", "Strict-Transport-Security": "max-age=86400",
                            "X-Content-Type-Options": "nosniff", "X-Wix-Request-Id": "1759673171.0000"},
                "body": www_home,
            },
        },
        "not_found": {"status": 404, "headers": HTML, "body": "<html><body>Not found</body></html>"},
        "tls": {"valid": True, "days_remaining": 74, "legacy_protocols": []},
    },
    "example.org": {
        "http": {
            "http://example.org/": {"status": 301, "headers": {"Location": "https://www.example.org/"}},
            "https://example.org/": {"status": 301, "headers": {"Location": "https://www.example.org/"}},
        },
        "tls": {"valid": True, "days_remaining": 74, "legacy_protocols": []},
        "dns": {
            "example.org": ["v=spf1 include:_spf.example.net ~all", "placeholder-site-verification=000000"],
            "_dmarc.example.org": [],
            "selector1._domainkey.example.org": ["v=DKIM1; k=rsa; p=PLACEHOLDERPUBLICKEY"],
        },
    },
    "archive.example.org": {
        "http": {
            "http://archive.example.org/": {
                "status": 200, "headers": {**HTML, "Server": "Apache/2.4.49 (Unix)"}, "body": archive_home,
            },
            "http://archive.example.org/backup.zip": {
                "status": 200, "headers": {"Content-Type": "application/zip", "Server": "Apache/2.4.49 (Unix)"},
                "body": "PK-placeholder-archive-bytes",
            },
        },
        "not_found": {"status": 404, "headers": HTML, "body": "<html><body>404 Not Found</body></html>"},
    },
    "staging.example.org": {
        "http": {
            "http://staging.example.org/": {
                "status": 200,
                "headers": {**HTML, "Server": "nginx/1.18.0 (Ubuntu)", "X-Frame-Options": "SAMEORIGIN"},
                "body": staging_home,
            },
            "http://staging.example.org/.git/HEAD": {
                "status": 200, "headers": {"Content-Type": "text/plain"}, "body": "ref: refs/heads/main\n",
            },
            "http://staging.example.org/.env": {
                "status": 200, "headers": {"Content-Type": "text/plain"},
                "body": "APP_ENV=staging\nDB_HOST=placeholder\nDB_PASSWORD=placeholder\n",
            },
        },
        "not_found": {"status": 404, "headers": HTML, "body": "<html><body>404</body></html>"},
    },
}

OUT.mkdir(parents=True, exist_ok=True)
for host, data in fixtures.items():
    (OUT / f"{host}.json").write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
print(f"wrote {len(fixtures)} fixtures to {OUT}")
