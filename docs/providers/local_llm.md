# Local LLM explanations

**Status:** 🚧 WIP: disabled by default, returns mock data from `data/mock/local_llm.json`

## What it adds
An optional "explain this finding" for findings the knowledge base does not cover, using a model running on this machine (Ollama or LM Studio).

## What data it sends externally
Nothing. The URL must be `localhost`; any other host is refused in code. Cloud AI APIs are not supported, by design, because of the NDA.

## Environment variables
`LOCAL_LLM_URL` (default `http://localhost:11434`), `LOCAL_LLM_MODEL`.

## Free vs paid
Free; needs a machine able to run the model. **Verify current pricing and terms yourself before enabling; they change.**

## Rate limits
None.

## Enabling it
Requires organization approval for this specific provider, then `"local_llm"` in `approved_providers`
(or `enabled_providers` if nothing leaves the machine), `WEBSCAN_LIVE_MODE=true`, and `--live`.
Try the mock output with `webscan demo --include-wip`.

## Steps to finish wiring it
1. Verify against a running Ollama (`/api/generate`) and add the LM Studio path (`/v1/chat/completions`).
2. Review output quality, especially in Spanish.
3. Show the text in reports with a clear "AI-generated, verify before acting" label.
4. Add `"local_llm"` to `enabled_providers`.
