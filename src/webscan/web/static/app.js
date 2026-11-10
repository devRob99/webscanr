// WebScan UI. Plain JavaScript, no framework, no build step.
//
// Security note: text that originates from a scanned site (finding names, evidence, headers)
// is only ever inserted with textContent. Nothing in this file uses innerHTML.
(function () {
  "use strict";

  var SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"];
  var GLYPHS = { Critical: "!!", High: "!", Medium: "~", Low: "-", Info: "i" };
  var STATUS_TEXT = {
    running: "Running", completed: "Completed", cancelled: "Cancelled", failed: "Failed", timed_out: "Timed out"
  };
  var POLL_MS = 600;

  var state = { apiBase: null, config: null, demo: false, pollTimer: null, renderToken: 0 };
  var main = document.getElementById("main");

  // ------------------------------------------------------------------ DOM helpers

  function h(tag, attrs, children) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (key) {
      var value = attrs[key];
      if (value === null || value === undefined || value === false) { return; }
      if (key === "class") { el.className = value; }
      else if (key === "text") { el.textContent = value; }
      else if (key.indexOf("on") === 0) { el.addEventListener(key.slice(2), value); }
      else if (value === true) { el.setAttribute(key, ""); }
      else { el.setAttribute(key, String(value)); }
    });
    [].concat(children || []).forEach(function (child) {
      if (child === null || child === undefined || child === false) { return; }
      el.appendChild(typeof child === "string" ? document.createTextNode(child) : child);
    });
    return el;
  }

  function clear(el) { while (el.firstChild) { el.removeChild(el.firstChild); } }

  function setPage(title, nodes) {
    clear(main);
    [].concat(nodes).forEach(function (n) { if (n) { main.appendChild(n); } });
    document.title = title ? title + " · WebScan" : "WebScan";
  }

  function notice(kind, message) {
    return h("div", { class: "notice notice-" + kind, role: kind === "error" ? "alert" : "status" }, [h("p", { text: message })]);
  }

  var toastTimer = null;
  function toast(message) {
    var el = document.getElementById("toast");
    el.textContent = message;
    window.clearTimeout(toastTimer);
    toastTimer = window.setTimeout(function () { el.textContent = ""; }, 4000);
  }

  function formatDate(iso) {
    if (!iso) { return ""; }
    var date = new Date(iso);
    return isNaN(date.getTime()) ? String(iso) : date.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
  }

  function severityBadge(severity) {
    return h("span", { class: "badge sev-" + severity.toLowerCase() }, [
      h("span", { class: "glyph", "aria-hidden": "true", text: GLYPHS[severity] || "" }), severity
    ]);
  }

  function statusPill(status) {
    var kind = { completed: "ok", running: "neutral", cancelled: "warn", failed: "err", timed_out: "err" }[status] || "neutral";
    return h("span", { class: "pill pill-" + kind, text: STATUS_TEXT[status] || status });
  }

  // ------------------------------------------------------------------ API

  function api(path, options) {
    options = options || {};
    var init = { method: options.method || "GET", headers: {} };
    if (options.body !== undefined) {
      init.headers["Content-Type"] = "application/json";
      init.body = JSON.stringify(options.body);
    }
    return fetch(state.apiBase + path, init).then(function (response) {
      if (options.blob && response.ok) { return response.blob(); }
      return response.json().catch(function () { return {}; }).then(function (data) {
        if (!response.ok) {
          var error = new Error(data.error || "The request failed (HTTP " + response.status + ").");
          error.status = response.status;
          throw error;
        }
        return data;
      });
    }, function () {
      throw new Error("Cannot reach the local WebScan API. Check that the server is still running.");
    });
  }

  function refreshConfig() {
    return api("/config").then(function (config) { state.config = config; return config; });
  }

  function download(path, filename) {
    return api(path, { blob: true }).then(function (blob) {
      var url = URL.createObjectURL(blob);
      var link = h("a", { href: url, download: filename });
      document.body.appendChild(link);
      link.click();
      link.remove();
      window.setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
    });
  }

  // ------------------------------------------------------------------ demo mode and theme

  function setDemo(on) {
    state.demo = on;
    try { window.sessionStorage.setItem("webscan-demo", on ? "1" : ""); } catch (err) { /* ignore */ }
    document.getElementById("demo-banner").hidden = !on;
  }

  function startDemo() {
    setDemo(true);
    return api("/scans", { method: "POST", body: { demo: true, scan_type: "full" } }).then(function (data) {
      location.hash = "#/scans/" + data.scan.id;
    }).catch(function (error) { toast(error.message); });
  }

  function currentTheme() {
    var explicit = document.documentElement.getAttribute("data-theme");
    if (explicit) { return explicit; }
    return window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  }

  function syncThemeButton() {
    var button = document.getElementById("theme-toggle");
    var dark = currentTheme() === "dark";
    button.textContent = dark ? "Light mode" : "Dark mode";
    button.setAttribute("aria-pressed", dark ? "true" : "false");
  }

  // ------------------------------------------------------------------ pages

  function pageLanding() {
    var live = state.config.live_mode;
    setPage("", [
      h("section", { class: "hero" }, [
        h("h1", { text: "Find and fix the security gaps on your own website" }),
        h("p", { class: "lede", text:
          "WebScan runs passive, non-destructive checks against a site you own, ranks what it finds by real-world " +
          "risk, and explains each issue in plain language with steps to fix it." }),
        h("div", { class: "actions" }, [
          h("a", { class: "btn btn-primary btn-large", href: "#/scan", text: "Start Scan" }),
          h("button", { class: "btn btn-large", type: "button", onclick: startDemo, text: "Try Demo" })
        ]),
        h("p", { class: "hint", text: "The demo uses built-in sample data for demo.example.com and sends no requests to any website." })
      ]),
      live ? null : notice("warn", state.config.live_mode_message),
      h("h2", { text: "How it works" }),
      h("div", { class: "grid-3" }, [
        h("div", { class: "card" }, [h("h3", { text: "1. Prove the site is yours" }), h("p", { class: "muted", text:
          "Add your domain and publish a one-time token as a DNS record or a small file. Unverified domains cannot be scanned." })]),
        h("div", { class: "card" }, [h("h3", { text: "2. Run a passive scan" }), h("p", { class: "muted", text:
          "Checks security headers, TLS, cookies, email protection, and more. Requests are throttled and you can cancel at any time." })]),
        h("div", { class: "card" }, [h("h3", { text: "3. Fix what matters first" }), h("p", { class: "muted", text:
          "Findings are grouped by severity with what was found, why it matters, and how to fix it. Export as PDF or JSON." })])
      ]),
      h("p", { class: "muted small" }, ["Only scan sites you own or have written permission to test. ", h("a", { href: "#/policy", text: "Usage policy" }), "."])
    ]);
  }

  function pagePolicy() {
    var limits = state.config.limits;
    function item(title, text) { return h("li", {}, [h("strong", { text: title + " " }), text]); }
    setPage("Usage policy", [
      h("h1", { text: "Usage policy and disclaimer" }),
      h("p", { class: "lede", text: "WebScan sends requests to real websites. Use it only where you are authorized to." }),
      h("div", { class: "card" }, [
        h("h2", { text: "Authorized use only" }),
        h("ul", {}, [
          item("Your sites only.", "Scan only websites you own, or for which you hold written permission from the owner to perform security testing."),
          item("Ownership is verified.", "Every public domain must pass DNS or file verification before it can be scanned. Verification expires after " +
            state.config.verification_ttl_days + " days and must be repeated. This is enforced by the server, not just hidden in this page."),
          item("You are responsible.", "Scanning systems without permission may be illegal where you live. You are responsible for how you use this tool."),
          item("Local apps.", "localhost and 127.0.0.1 can be scanned without verification so you can test an app running on this computer.")
        ])
      ]),
      h("div", { class: "card" }, [
        h("h2", { text: "What the scanner does and does not do" }),
        h("ul", {}, [
          item("Passive checks only.", "It makes the same kind of requests a browser or mail server makes: page loads, a TLS handshake, DNS lookups, and a few requests for commonly exposed file names."),
          item("Nothing destructive.", "No exploit payloads, no login guessing, no form submissions, no load or denial-of-service testing."),
          item("Stays in scope.", "Only the verified host is contacted. Redirects and links to other domains are never followed. Private, internal, and cloud metadata addresses are blocked."),
          item("Throttled.", "At most " + limits.max_requests_per_second + " requests per second per site, " + limits.max_concurrent_scans +
            " scans at once, and a " + limits.scan_cooldown_seconds + "-second pause between scans of the same domain."),
          item("Identifies itself.", "Every request carries this User-Agent: "),
        ]),
        h("p", {}, [h("code", { text: state.config.user_agent })]),
        h("ul", {}, [item("Logged.", "Each scan is recorded in the audit log with the domain, time, verification method, and result summary.")])
      ]),
      h("div", { class: "card" }, [
        h("h2", { text: "Disclaimer" }),
        h("p", { text: "Results are a starting point, not a guarantee. A clean report does not mean a site is secure, and some findings are inferences that should be confirmed before acting. WebScan is a prototype provided as is, without warranty." }),
        h("p", { text: "Reports describe weaknesses in a website. Treat them as confidential." })
      ])
    ]);
  }

  // ---- Domains

  function copyRow(label, value) {
    var button = h("button", { class: "btn btn-small", type: "button", "aria-label": "Copy " + label, text: "Copy" });
    button.addEventListener("click", function () {
      var done = function () { button.textContent = "Copied"; window.setTimeout(function () { button.textContent = "Copy"; }, 1500); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(value).then(done, function () { toast("Copy failed. Select the text and copy it manually."); });
      } else { toast("Select the text and copy it manually."); }
    });
    return h("div", {}, [h("div", { class: "label", text: label }), h("div", { class: "copy-row" }, [h("code", { text: value }), button])]);
  }

  function verificationPanel(domain, onChange, demo) {
    var result = h("div", { "aria-live": "polite" });
    function check(method, button) {
      if (demo) { toast("Demo mode: verification is simulated. Nothing is sent."); return; }
      var label = button.textContent;
      button.disabled = true; button.textContent = "Checking…";
      api("/domains/" + encodeURIComponent(domain.name) + "/verify", { method: "POST", body: { method: method } })
        .then(function (data) {
          if (data.ok) { toast(domain.name + " is verified."); onChange(); return; }
          clear(result); result.appendChild(notice("error", "Verification failed. " + data.detail));
        })
        .catch(function (error) { clear(result); result.appendChild(notice("error", error.message)); })
        .then(function () { button.disabled = false; button.textContent = label; });
    }
    var dns = domain.instructions.dns, file = domain.instructions.file;
    var dnsButton = h("button", { class: "btn btn-primary", type: "button", text: "Check Verification (DNS)" });
    dnsButton.addEventListener("click", function () { check("dns", dnsButton); });
    var fileButton = h("button", { class: "btn btn-primary", type: "button", text: "Check Verification (file)" });
    fileButton.addEventListener("click", function () { check("file", fileButton); });
    return h("div", {}, [
      h("p", { text: "Prove you control this domain using either method, then check verification." }),
      h("div", { class: "grid-2" }, [
        h("div", { class: "method" }, [
          h("h3", { text: "Option 1: DNS TXT record" }),
          h("p", { class: "muted small", text: "Add this record at your DNS provider. Changes can take a few minutes to appear." }),
          copyRow("Record name (host)", dns.name),
          copyRow("Record value (TXT)", dns.value),
          h("p", { class: "hint", text: "Alternatively use the name " + dns.alt_name + " with the same value." }),
          h("div", { class: "actions" }, [dnsButton])
        ]),
        h("div", { class: "method" }, [
          h("h3", { text: "Option 2: Upload a file" }),
          h("p", { class: "muted small", text: "Create a plain text file at this address containing only the token. It must be served over HTTPS without a redirect." }),
          copyRow("File address", file.url),
          copyRow("File content", file.content),
          h("div", { class: "actions" }, [fileButton])
        ])
      ]),
      result
    ]);
  }

  function domainCard(domain, onChange, demo) {
    var pill = {
      verified: h("span", { class: "pill pill-ok", text: "✓ Verified" }),
      exempt: h("span", { class: "pill pill-ok", text: "✓ Local (no verification needed)" }),
      expired: h("span", { class: "pill pill-warn", text: "! Verification expired" }),
      unverified: h("span", { class: "pill pill-err", text: "✕ Unverified" })
    }[domain.status];
    var ready = domain.status === "verified" || domain.status === "exempt";
    var remove = h("button", { class: "btn btn-small btn-danger", type: "button", "aria-label": "Remove " + domain.name, text: "Remove" });
    remove.addEventListener("click", function () {
      if (demo) { toast("Demo mode: the sample domain cannot be removed."); return; }
      if (!window.confirm("Remove " + domain.name + "? Its verification will be forgotten. Past scans are kept.")) { return; }
      api("/domains/" + encodeURIComponent(domain.name), { method: "DELETE" }).then(onChange, function (error) { toast(error.message); });
    });
    var details = [];
    if (domain.status === "verified") {
      details.push(h("dl", { class: "meta" }, [
        h("dt", { text: "Method" }), h("dd", { text: domain.method === "dns" ? "DNS TXT record" : "Verification file" }),
        h("dt", { text: "Verified" }), h("dd", { text: formatDate(domain.verified_at) }),
        h("dt", { text: "Expires" }), h("dd", { text: formatDate(domain.expires_at) })
      ]));
    }
    if (domain.status === "expired") {
      details.push(notice("warn", "Verification expired on " + formatDate(domain.expires_at) + ". Check verification again to keep scanning."));
    }
    if (domain.kind === "public") {
      var panel = verificationPanel(domain, onChange, demo);
      details.push(ready ? h("details", {}, [h("summary", { text: "Show verification instructions" }), panel]) : panel);
    }
    return h("div", { class: "card" }, [
      h("div", { class: "card-head" }, [
        h("h3", { text: domain.name }),
        h("div", { class: "actions" }, [
          pill,
          ready ? h("a", { class: "btn btn-small btn-primary", href: "#/scan/" + encodeURIComponent(domain.name), text: "Scan" }) : null,
          remove
        ])
      ])
    ].concat(details));
  }

  function demoDomain() {
    var token = "DEMO-TOKEN-not-a-real-value";
    return {
      name: state.config.demo_target, host: state.config.demo_target, kind: "public", status: "verified", method: "dns",
      verified_at: new Date(Date.now() - 3 * 86400000).toISOString(),
      expires_at: new Date(Date.now() + (state.config.verification_ttl_days - 3) * 86400000).toISOString(),
      instructions: {
        dns: { name: state.config.demo_target, alt_name: "_scanner-verify." + state.config.demo_target, value: "scanner-verify=" + token },
        file: { url: "https://" + state.config.demo_target + "/.well-known/scanner-verify.txt", content: token }
      }
    };
  }

  function pageDomains() {
    var token = state.renderToken;
    var list = h("div", { "aria-live": "polite" });
    var error = h("div");
    var input = h("input", { type: "text", id: "domain-input", name: "domain", autocomplete: "off", spellcheck: "false",
      placeholder: "example.org", maxlength: "260", "aria-describedby": "domain-hint", required: true });

    function load() {
      if (state.demo) {
        clear(list); list.appendChild(domainCard(demoDomain(), load, true)); return Promise.resolve();
      }
      return api("/domains").then(function (data) {
        if (token !== state.renderToken) { return; }
        clear(list);
        if (!data.domains.length) {
          list.appendChild(h("div", { class: "card empty", text: "No domains yet. Add the domain of a site you own to get started." }));
        }
        data.domains.forEach(function (domain) { list.appendChild(domainCard(domain, load, false)); });
      }).catch(function (err) { clear(list); list.appendChild(notice("error", err.message)); });
    }

    var form = h("form", { class: "card", novalidate: true }, [
      h("div", { class: "field-row" }, [
        h("div", { class: "grow" }, [h("label", { for: "domain-input", text: "Domain" }), input]),
        h("button", { class: "btn btn-primary", type: "submit", text: "Add domain" })
      ]),
      h("p", { class: "hint", id: "domain-hint", text: "Enter only the hostname, for example example.org or www.example.org. Use localhost:3000 to test a local app." }),
      error
    ]);
    form.addEventListener("submit", function (event) {
      event.preventDefault();
      clear(error);
      if (state.demo) { toast("Demo mode: exit the demo to add your own domain."); return; }
      // Convenience only: the server validates the value again.
      var value = input.value.trim().replace(/^https?:\/\//i, "").replace(/\/.*$/, "");
      if (!value) { error.appendChild(notice("error", "Enter a domain name.")); input.focus(); return; }
      api("/domains", { method: "POST", body: { domain: value } })
        .then(function () { input.value = ""; return load(); })
        .catch(function (err) { error.appendChild(notice("error", err.message)); input.focus(); });
    });

    setPage("Domains", [
      h("h1", { text: "Domains" }),
      h("p", { class: "lede", text: "Add the sites you own. A public domain must be verified before it can be scanned, and each hostname is verified separately." }),
      !state.demo && !state.config.live_mode ? notice("warn", state.config.live_mode_message) : null,
      form, h("h2", { text: "Your domains" }), list
    ]);
    load();
  }

  // ---- New scan

  function pageScan(preselect) {
    var token = state.renderToken;
    var error = h("div");
    var select = h("select", { id: "scan-domain", name: "domain", required: true });
    var types = h("div", { class: "choices" }, state.config.scan_types.map(function (type, index) {
      return h("label", { class: "choice" }, [
        h("input", { type: "radio", name: "scan-type", value: type.id, checked: index === 0 }),
        h("strong", { text: type.label }), h("span", { class: "muted small", text: type.description })
      ]);
    }));
    var acknowledged = Boolean(state.config.acknowledged_at) || state.demo;
    var ackBox = h("input", { type: "checkbox", id: "ack", name: "ack", required: true });
    var ack = acknowledged ? null : h("div", { class: "field" }, [
      h("label", { class: "check", for: "ack" }, [ackBox,
        h("span", {}, ["I confirm that I own this site or have written permission from its owner to test it. ",
          h("a", { href: "#/policy", text: "Usage policy" })])
      ])
    ]);
    var submit = h("button", { class: "btn btn-primary btn-large", type: "submit", text: "Start Scan" });
    var form = h("form", { class: "card", novalidate: true }, [
      h("div", { class: "field" }, [h("label", { for: "scan-domain", text: "Domain" }), select,
        h("p", { class: "hint" }, ["Only verified domains can be scanned. ", h("a", { href: "#/domains", text: "Manage domains" })])]),
      h("fieldset", {}, [h("legend", { text: "Scan type" }), types]),
      ack, error, h("div", { class: "actions" }, [submit])
    ]);

    form.addEventListener("submit", function (event) {
      event.preventDefault();
      clear(error);
      var scanType = form.querySelector('input[name="scan-type"]:checked').value;
      if (!state.demo && !select.value) { error.appendChild(notice("error", "Choose a verified domain to scan.")); select.focus(); return; }
      if (ack && !ackBox.checked) { error.appendChild(notice("error", "Tick the box to confirm you are authorized to test this site.")); ackBox.focus(); return; }
      submit.disabled = true;
      var before = ack ? api("/acknowledgment", { method: "POST", body: { accepted: true } }).then(refreshConfig) : Promise.resolve();
      before.then(function () {
        return api("/scans", { method: "POST", body: state.demo ? { demo: true, scan_type: scanType } : { domain: select.value, scan_type: scanType } });
      }).then(function (data) { location.hash = "#/scans/" + data.scan.id; })
        .catch(function (err) { error.appendChild(notice("error", err.message)); submit.disabled = false; });
    });

    setPage("Scan", [
      h("h1", { text: "Start a scan" }),
      h("p", { class: "lede", text: "Passive, non-destructive checks against one verified site. You can cancel at any time." }),
      !state.demo && !state.config.live_mode ? notice("warn", state.config.live_mode_message) : null,
      form
    ]);

    if (state.demo) {
      select.appendChild(h("option", { value: state.config.demo_target, text: state.config.demo_target + " (demo)" }));
      select.disabled = true;
      return;
    }
    api("/domains").then(function (data) {
      if (token !== state.renderToken) { return; }
      var usable = 0;
      select.appendChild(h("option", { value: "", text: "Choose a domain" }));
      data.domains.forEach(function (domain) {
        var ready = domain.status === "verified" || domain.status === "exempt";
        if (ready) { usable += 1; }
        select.appendChild(h("option", { value: domain.name, disabled: !ready, selected: ready && domain.name === preselect,
          text: domain.name + (ready ? "" : domain.status === "expired" ? " (verification expired)" : " (not verified)") }));
      });
      if (!usable) {
        error.appendChild(notice("warn", "You have no verified domains yet. Add and verify a domain first, or try the demo."));
        submit.disabled = true;
      }
    }).catch(function (err) { error.appendChild(notice("error", err.message)); });
  }

  // ---- Scan progress and results

  function pageScanDetail(id) {
    var token = state.renderToken;
    function tick() {
      api("/scans/" + encodeURIComponent(id)).then(function (data) {
        if (token !== state.renderToken) { return; }
        var scan = data.scan;
        if (scan.mode === "demo" && !state.demo) { setDemo(true); }
        if (scan.status === "running") {
          renderProgress(scan);
          state.pollTimer = window.setTimeout(tick, POLL_MS);
        } else if (scan.status === "completed" && scan.result) {
          renderResults(scan);
        } else {
          renderStopped(scan);
        }
      }).catch(function (error) {
        if (token !== state.renderToken) { return; }
        setPage("Scan", [h("h1", { text: "Scan" }), notice("error", error.message),
          h("a", { class: "btn", href: "#/history", text: "Back to history" })]);
      });
    }
    setPage("Scan", [h("p", { class: "muted", text: "Loading…" })]);
    tick();
  }

  var progressView = null;
  function renderProgress(scan) {
    if (!progressView || progressView.id !== scan.id || !main.contains(progressView.root)) {
      var bar = h("progress", { max: "100", value: "0", "aria-label": "Scan progress" });
      var current = h("p", { class: "current-check", "aria-live": "polite" });
      var steps = h("ol", { class: "steps" });
      var cancel = h("button", { class: "btn btn-danger", type: "button", text: "Cancel scan" });
      cancel.addEventListener("click", function () {
        cancel.disabled = true;
        window.clearTimeout(state.pollTimer);
        api("/scans/" + encodeURIComponent(scan.id) + "/cancel", { method: "POST", body: {} })
          .then(function (data) { renderStopped(data.scan); })
          .catch(function (error) { toast(error.message); cancel.disabled = false; });
      });
      var root = h("div", { class: "card" }, [bar, current, steps, h("div", { class: "actions" }, [cancel])]);
      progressView = { id: scan.id, root: root, bar: bar, current: current, steps: steps };
      setPage("Scanning " + scan.target, [
        h("h1", { text: "Scanning " + scan.target }),
        h("p", { class: "muted", text: (scan.scan_type === "full" ? "Full scan" : "Quick scan") + " · started " + formatDate(scan.started_at) }),
        root
      ]);
    }
    var progress = scan.progress;
    progressView.bar.value = progress.percent;
    var label = progress.current ? "Current check: " + progress.current : "Finishing…";
    if (progressView.current.textContent !== label) { progressView.current.textContent = label; }
    clear(progressView.steps);
    progress.steps.forEach(function (step, index) {
      var stepState = index < progress.step_index ? "done" : index === progress.step_index ? "current" : "pending";
      progressView.steps.appendChild(h("li", { "data-state": stepState }, [
        h("span", { class: "mark", "aria-hidden": "true", text: { done: "✓", current: "●", pending: "○" }[stepState] }),
        h("span", {}, [step, h("span", { class: "sr-only", text: " (" + stepState + ")" })])
      ]));
    });
  }

  function renderStopped(scan) {
    var messages = {
      cancelled: "This scan was cancelled. No further requests were sent.",
      timed_out: scan.error || "The scan timed out.",
      failed: scan.error || "The scan failed."
    };
    setPage("Scan " + (STATUS_TEXT[scan.status] || ""), [
      h("h1", { text: "Scan of " + scan.target }),
      h("p", {}, [statusPill(scan.status), " ", h("span", { class: "muted", text: "Started " + formatDate(scan.started_at) })]),
      notice(scan.status === "cancelled" ? "warn" : "error", messages[scan.status] || "The scan did not complete."),
      h("div", { class: "actions" }, [
        h("a", { class: "btn btn-primary", href: "#/scan", text: "Start another scan" }),
        h("a", { class: "btn", href: "#/history", text: "View history" })
      ])
    ]);
  }

  function findingCard(finding) {
    var body = [
      h("h4", { text: "What was found" }), h("p", { text: finding.what }),
      finding.evidence ? h("div", { class: "evidence", text: finding.evidence }) : null,
      h("h4", { text: "Where" }),
      h("p", { text: finding.asset + (finding.asset_description ? " (" + finding.asset_description + ")" : "") }),
      h("h4", { text: "Why it matters" }), h("p", { text: finding.why }),
      h("h4", { text: "How to fix it" }),
      finding.platform_note ? h("p", { class: "muted", text: finding.platform_note }) : null,
      h("ol", {}, (finding.fix || []).map(function (step) { return h("li", { text: step }); }))
    ];
    var tags = [];
    if (finding.cve) { tags.push(h("span", { class: "pill pill-neutral", text: finding.cve })); }
    if (finding.kev) { tags.push(h("span", { class: "pill pill-err", text: "Actively exploited (CISA KEV)" })); }
    else if (finding.exploit) { tags.push(h("span", { class: "pill pill-warn", text: "Public exploit exists" })); }
    tags.push(h("span", { class: "pill pill-neutral", text: "Risk score " + finding.risk + " / 100" }));
    tags.push(h("span", { class: "pill pill-neutral", text: "CVSS " + finding.cvss }));
    body.push(h("h4", { text: "Technical details" }), h("div", { class: "tags" }, tags));
    if (finding.name && finding.name !== finding.title) { body.push(h("p", { class: "muted small", text: "Scanner name: " + finding.name })); }
    if (finding.references && finding.references.length) {
      // Shown as text, never as links: reference strings can come from scanned content.
      body.push(h("p", { class: "muted small mono", text: "References: " + finding.references.join(", ") }));
    }
    return h("details", { class: "finding", "data-severity": finding.priority }, [
      h("summary", {}, [severityBadge(finding.priority), h("span", { class: "title", text: finding.title }),
        h("span", { class: "where", text: finding.asset })]),
      h("div", { class: "body" }, body)
    ]);
  }

  function renderResults(scan) {
    var result = scan.result, summary = result.summary, filter = null;
    var list = h("div");
    var listHeading = h("h2", { id: "findings-heading", tabindex: "-1" });
    var tiles = {};

    function drawList() {
      clear(list);
      var shown = result.findings.filter(function (f) { return !filter || f.priority === filter; });
      listHeading.textContent = (filter ? filter + " findings" : "All findings") + " (" + shown.length + ")";
      if (!shown.length) {
        list.appendChild(h("div", { class: "card empty", text: result.findings.length ? "No findings at this severity." : "No issues were found by these checks." }));
      }
      shown.forEach(function (finding) { list.appendChild(findingCard(finding)); });
      SEVERITIES.forEach(function (s) { tiles[s].setAttribute("aria-pressed", filter === s ? "true" : "false"); });
    }

    var summaryRow = h("div", { class: "summary" }, [
      h("div", { class: "card grade" }, [
        h("span", { class: "muted small", text: "Overall grade" }), h("span", { class: "letter", text: summary.grade }),
        h("span", { class: "muted small", text: summary.total + (summary.total === 1 ? " finding" : " findings") })
      ])
    ].concat(SEVERITIES.map(function (severity) {
      var tile = h("button", { class: "tile sev-" + severity.toLowerCase(), type: "button", "aria-pressed": "false",
        "aria-label": summary.counts[severity] + " " + severity + " findings. Toggle filter." }, [
        h("span", { class: "count", text: String(summary.counts[severity] || 0) }),
        h("span", { class: "name" }, [h("span", { class: "glyph mono", "aria-hidden": "true", text: GLYPHS[severity] + " " }), severity])
      ]);
      tile.addEventListener("click", function () { filter = filter === severity ? null : severity; drawList(); });
      tiles[severity] = tile;
      return tile;
    })));

    var base = "/scans/" + encodeURIComponent(scan.id);
    var stem = "webscan-" + scan.target.replace(/[^a-z0-9.-]/gi, "-") + "-" + String(scan.started_at).slice(0, 10);
    function exportButton(label, path, name) {
      var button = h("button", { class: "btn", type: "button", text: label });
      button.addEventListener("click", function () {
        button.disabled = true;
        download(path, name).catch(function (error) { toast(error.message); }).then(function () { button.disabled = false; });
      });
      return button;
    }

    var fixFirst = (result.fix_first || []).map(function (item, index) {
      return h("div", { class: "card" }, [
        h("div", { class: "card-head" }, [h("h3", { text: (index + 1) + ". " + item.title }), severityBadge(item.priority)]),
        h("p", { class: "muted small", text: item.clears + " · Effort: " + item.effort }),
        h("p", { text: item.why })
      ]);
    });

    setPage("Results for " + scan.target, [
      h("h1", { text: "Results for " + scan.target }),
      h("p", { class: "muted", text: (scan.scan_type === "full" ? "Full scan" : "Quick scan") + " · " + formatDate(scan.finished_at || scan.started_at) +
        (scan.mode === "demo" ? " · demo data" : "") }),
      h("div", { class: "actions" }, [
        exportButton("Export PDF", base + "/report.pdf", stem + ".pdf"),
        exportButton("Export JSON", base + "/report.json", stem + ".json"),
        h("a", { class: "btn", href: state.apiBase + base + "/report.html", target: "_blank", rel: "noopener noreferrer", text: "Printable report" }),
        h("a", { class: "btn", href: "#/history", text: "History and compare" })
      ]),
      summaryRow,
      h("p", { text: summary.paragraph }),
      (result.warnings || []).length ? h("details", { class: "notice notice-warn" }, [
        h("summary", { text: "Scanner notes (" + result.warnings.length + ")" })
      ].concat(result.warnings.map(function (w) { return h("p", { text: w }); }))) : null,
      fixFirst.length ? h("h2", { text: "Fix these first" }) : null,
      fixFirst.length ? h("div", { class: "grid-3" }, fixFirst) : null,
      listHeading,
      h("p", { class: "muted small", text: "Select a finding to see what was found, where, why it matters, and how to fix it. Use the severity tiles above to filter." }),
      list
    ]);
    drawList();
  }

  // ---- History and compare

  function countsCell(counts) {
    if (!counts) { return h("span", { class: "muted", text: "—" }); }
    return h("div", { class: "counts" }, SEVERITIES.filter(function (s) { return counts[s]; }).map(function (s) {
      return h("span", { class: "badge sev-" + s.toLowerCase(), text: counts[s] + " " + s });
    }));
  }

  function pageHistory() {
    var token = state.renderToken;
    var selected = [];
    var body = h("div");
    var compare = h("button", { class: "btn btn-primary", type: "button", disabled: true, text: "Compare selected" });
    var hint = h("span", { class: "muted small", "aria-live": "polite", text: "Select two completed scans of the same domain to compare them." });

    function sync(scans) {
      var picked = scans.filter(function (s) { return selected.indexOf(s.id) !== -1; });
      var ok = picked.length === 2 && picked[0].target === picked[1].target;
      compare.disabled = !ok;
      hint.textContent = picked.length === 2 && !ok ? "Those scans are for different domains. Choose two scans of the same domain."
        : "Select two completed scans of the same domain to compare them.";
    }

    compare.addEventListener("click", function () {
      location.hash = "#/compare/" + encodeURIComponent(selected[0]) + "/" + encodeURIComponent(selected[1]);
    });

    setPage("History", [
      h("h1", { text: "Scan history" }),
      h("p", { class: "lede", text: state.demo ? "Sample scans of the fictional demo site." : "Every scan you have run, newest first." }),
      h("div", { class: "toolbar" }, [hint, compare]), body
    ]);

    api("/scans?demo=" + (state.demo ? "true" : "false")).then(function (data) {
      if (token !== state.renderToken) { return; }
      var scans = data.scans;
      if (!scans.length) {
        body.appendChild(h("div", { class: "card empty" }, ["No scans yet. ", h("a", { href: "#/scan", text: "Start a scan" }), "."]));
        return;
      }
      var rows = scans.map(function (scan) {
        var done = scan.status === "completed";
        var box = h("input", { type: "checkbox", disabled: !done, "aria-label": "Select scan of " + scan.target + " from " + formatDate(scan.started_at) + " for comparison" });
        box.addEventListener("change", function () {
          if (box.checked) {
            selected.push(scan.id);
            if (selected.length > 2) {
              var dropped = selected.shift();
              var other = body.querySelector('input[data-id="' + dropped + '"]');
              if (other) { other.checked = false; }
            }
          } else { selected = selected.filter(function (id) { return id !== scan.id; }); }
          sync(scans);
        });
        box.setAttribute("data-id", scan.id);
        return h("tr", {}, [
          h("td", {}, [box]),
          h("td", {}, [h("a", { href: "#/scans/" + encodeURIComponent(scan.id), text: scan.target })]),
          h("td", { text: formatDate(scan.started_at) }),
          h("td", { text: scan.scan_type === "full" ? "Full" : "Quick" }),
          h("td", {}, [statusPill(scan.status)]),
          h("td", { text: scan.grade || "—" }),
          h("td", {}, [countsCell(scan.counts)])
        ]);
      });
      body.appendChild(h("div", { class: "table-wrap" }, [h("table", {}, [
        h("caption", { class: "sr-only", text: "Past scans" }),
        h("thead", {}, [h("tr", {}, ["Compare", "Domain", "Started", "Type", "Status", "Grade", "Findings"].map(function (t) { return h("th", { scope: "col", text: t }); }))]),
        h("tbody", {}, rows)
      ])]));
    }).catch(function (error) { body.appendChild(notice("error", error.message)); });
  }

  function pageCompare(a, b) {
    var token = state.renderToken;
    setPage("Compare", [h("p", { class: "muted", text: "Loading…" })]);
    api("/compare?previous=" + encodeURIComponent(a) + "&current=" + encodeURIComponent(b)).then(function (data) {
      if (token !== state.renderToken) { return; }
      var diff = data.comparison;
      function section(title, items, emptyText) {
        return h("section", {}, [
          h("h2", { text: title + " (" + items.length + ")" }),
          items.length ? h("div", {}, items.map(function (item) {
            return h("div", { class: "card" }, [h("div", { class: "card-head" }, [
              h("h3", { text: item.name }),
              h("div", { class: "actions" }, [
                item.previous_risk_score !== undefined ? h("span", { class: "muted small", text: "Risk " + item.previous_risk_score + " → " + item.risk_score }) : null,
                severityBadge(item.priority)
              ])
            ]), h("p", { class: "muted small", text: item.asset_name })]);
          })) : h("p", { class: "muted", text: emptyText })
        ]);
      }
      setPage("Compare scans", [
        h("h1", { text: "What changed on " + diff.target }),
        h("div", { class: "grid-2" }, [
          h("div", { class: "card" }, [h("h3", { text: "Earlier scan" }), h("p", { class: "muted", text: formatDate(diff.previous.created_at) }),
            h("p", {}, ["Grade ", h("strong", { text: diff.previous.grade }), " · " + diff.previous.total + " findings ",
              h("a", { href: "#/scans/" + encodeURIComponent(diff.previous.id), text: "View report" })])]),
          h("div", { class: "card" }, [h("h3", { text: "Later scan" }), h("p", { class: "muted", text: formatDate(diff.current.created_at) }),
            h("p", {}, ["Grade ", h("strong", { text: diff.current.grade }), " · " + diff.current.total + " findings ",
              h("a", { href: "#/scans/" + encodeURIComponent(diff.current.id), text: "View report" })])])
        ]),
        h("p", {}, [
          h("span", { class: "pill pill-ok", text: "✓ " + diff.resolved.length + " fixed" }), " ",
          h("span", { class: "pill pill-err", text: "+ " + diff.new.length + " new" }), " ",
          h("span", { class: "pill pill-warn", text: "↑ " + diff.worse.length + " got worse" }), " ",
          h("span", { class: "pill pill-neutral", text: "= " + diff.unchanged + " unchanged" })
        ]),
        section("Fixed", diff.resolved, "Nothing was fixed between these scans."),
        section("Newly introduced", diff.new, "No new findings."),
        section("Got worse", diff.worse, "No findings increased in risk."),
        h("div", { class: "actions" }, [h("a", { class: "btn", href: "#/history", text: "Back to history" })])
      ]);
    }).catch(function (error) {
      if (token !== state.renderToken) { return; }
      setPage("Compare", [h("h1", { text: "Compare scans" }), notice("error", error.message), h("a", { class: "btn", href: "#/history", text: "Back to history" })]);
    });
  }

  // ---- Audit log

  function pageAudit() {
    var token = state.renderToken;
    var body = h("div");
    setPage("Audit log", [
      h("h1", { text: "Audit log" }),
      h("p", { class: "lede", text: "A record of every scan and verification: the domain, when it happened, how ownership was verified, and the outcome." }),
      body
    ]);
    if (state.demo) { body.appendChild(notice("warn", "Demo scans are not written to the audit log. Exit the demo to see real entries.")); return; }
    api("/audit").then(function (data) {
      if (token !== state.renderToken) { return; }
      if (!data.entries.length) { body.appendChild(h("div", { class: "card empty", text: "Nothing has been recorded yet." })); return; }
      var methods = { dns: "DNS TXT record", file: "Verification file", "loopback-exempt": "Local address (exempt)" };
      body.appendChild(h("div", { class: "table-wrap" }, [h("table", {}, [
        h("caption", { class: "sr-only", text: "Audit log entries" }),
        h("thead", {}, [h("tr", {}, ["Time", "Event", "Domain", "Verification", "Result"].map(function (t) { return h("th", { scope: "col", text: t }); }))]),
        h("tbody", {}, data.entries.map(function (entry) {
          return h("tr", {}, [
            h("td", { text: formatDate(entry.timestamp) }),
            h("td", { text: String(entry.event).replace(/_/g, " ") }),
            h("td", { text: entry.target || "—" }),
            h("td", { text: methods[entry.verification_method] || entry.verification_method || "—" }),
            h("td", { text: entry.summary || entry.status })
          ]);
        }))
      ])]));
    }).catch(function (error) { body.appendChild(notice("error", error.message)); });
  }

  // ------------------------------------------------------------------ router

  function route() {
    window.clearTimeout(state.pollTimer);
    state.renderToken += 1;
    var parts = location.hash.replace(/^#\/?/, "").split("/").map(decodeURIComponent);
    var name = parts[0] || "";
    var nav = { scans: "scan", compare: "history" }[name] || name;
    Array.prototype.forEach.call(document.querySelectorAll("[data-nav]"), function (link) {
      if (link.getAttribute("data-nav") === nav) { link.setAttribute("aria-current", "page"); }
      else { link.removeAttribute("aria-current"); }
    });
    if (name === "") { pageLanding(); }
    else if (name === "domains") { pageDomains(); }
    else if (name === "scan") { pageScan(parts[1] || ""); }
    else if (name === "scans" && parts[1]) { pageScanDetail(parts[1]); }
    else if (name === "history") { pageHistory(); }
    else if (name === "compare" && parts[1] && parts[2]) { pageCompare(parts[1], parts[2]); }
    else if (name === "audit") { pageAudit(); }
    else if (name === "policy") { pagePolicy(); }
    else { setPage("Not found", [h("h1", { text: "Page not found" }), h("a", { class: "btn", href: "#/", text: "Go to the start page" })]); }
    window.scrollTo(0, 0);
  }

  function boot() {
    document.getElementById("theme-toggle").addEventListener("click", function () {
      var next = currentTheme() === "dark" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      try { window.localStorage.setItem("webscan-theme", next); } catch (err) { /* ignore */ }
      syncThemeButton();
    });
    syncThemeButton();
    document.getElementById("exit-demo").addEventListener("click", function () {
      setDemo(false);
      if (location.hash === "#/" || location.hash === "") { route(); } else { location.hash = "#/"; }
    });
    try { state.demo = window.sessionStorage.getItem("webscan-demo") === "1"; } catch (err) { state.demo = false; }
    document.getElementById("demo-banner").hidden = !state.demo;

    fetch("config.json").then(function (response) { return response.json(); }).then(function (config) {
      state.apiBase = config.apiBase;
      return refreshConfig();
    }).then(function () {
      window.addEventListener("hashchange", function () { route(); main.focus({ preventScroll: true }); });
      route();
    }).catch(function (error) {
      setPage("", [h("h1", { text: "WebScan could not start" }),
        notice("error", error && error.message ? error.message : "Cannot reach the local WebScan API. Check that the server is still running.")]);
    });
  }

  boot();
})();
