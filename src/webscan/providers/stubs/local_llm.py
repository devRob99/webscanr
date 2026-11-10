"""Local LLM explanations ("explain this finding").

STATUS: 🚧 WIP
Purpose: optional extra plain-language explanation for findings the knowledge base does not cover.
Env vars: LOCAL_LLM_URL (default http://localhost:11434), LOCAL_LLM_MODEL
Planned endpoints (local only):
  Ollama:    POST <url>/api/generate           {"model", "prompt", "stream": false}
  LM Studio: POST <url>/v1/chat/completions    (OpenAI-compatible)
Data that would leave the org: none. The URL must point at this machine (localhost); any other
        host is refused. Cloud AI APIs are deliberately not supported (NDA).
TODO: verify against a running Ollama / LM Studio; tune the prompt; review output quality in
      Spanish; add a visible "AI-generated, verify before acting" label wherever it is shown.
"""

from __future__ import annotations

import time
from typing import Any
from urllib.parse import urlsplit

from webscan.models import Finding, Issue
from webscan.providers.stubs.base import StubProvider

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}
DEFAULT_URL = "http://localhost:11434"


class LocalLlmError(Exception):
    pass


class LocalLlmProvider(StubProvider):
    name = "local_llm"
    is_external = False  # only ever talks to this machine
    env_vars = ("LOCAL_LLM_URL", "LOCAL_LLM_MODEL")
    accepts = frozenset()  # not target-driven: use explain()
    data_sent = "nothing (local model only)"

    def _fetch_live(self, target: str) -> Any | None:
        return None

    def _parse(self, target: str, payload: Any) -> list[Issue]:
        return []

    def endpoint(self) -> str:
        url = self.ctx.settings.get_env("LOCAL_LLM_URL") or DEFAULT_URL
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or (parts.hostname or "").lower() not in LOCAL_HOSTS:
            raise LocalLlmError("LOCAL_LLM_URL must point to this machine (localhost). Remote AI services are not allowed.")
        return url.rstrip("/")

    def build_prompt(self, finding: Finding, lang: str) -> str:
        language = "Spanish (formal, use 'usted')" if lang == "es" else "English"
        # Only already-redacted fields are used, so no raw hostname or IP reaches the model.
        return (
            f"You are helping a nonprofit's non-technical leadership. In {language}, explain in three short "
            "paragraphs: what this security finding means, why it matters to a nonprofit and its donors, and "
            "how to fix it. No jargon.\n\n"
            f"Finding: {finding.vulnerability_name}\nCVE: {finding.cve_id or 'none'}\n"
            f"Scanner description: {finding.description or 'none'}\n"
        )

    def explain(self, finding: Finding, lang: str = "en") -> str | None:
        """Plain-language explanation from the local model, or mock text when not live."""
        if not self.is_live():
            mock = self.mock_data().get("responses", {})
            return (mock.get(finding.knowledge_id or "") or mock.get("default", {})).get(lang)
        import requests

        url = self.endpoint()  # refuses anything that is not localhost
        self.ctx.guard.authorize_provider(self.name, third_party=False)
        model = self.ctx.settings.get_env("LOCAL_LLM_MODEL") or "llama3.1"
        started = time.perf_counter()
        status = "error"
        try:
            # TODO: verify against live API (Ollama shown; LM Studio uses /v1/chat/completions)
            response = requests.post(
                f"{url}/api/generate",
                json={"model": model, "prompt": self.build_prompt(finding, lang), "stream": False}, timeout=120,
            )
            response.raise_for_status()
            status = "ok"
            return str(response.json().get("response", "")).strip() or None
        finally:
            self.ctx.audit.log("api_call", provider=self.name, mode="live", status=status,
                               duration_ms=(time.perf_counter() - started) * 1000)
