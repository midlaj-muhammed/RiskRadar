# BYO Model Providers

RiskRadar supports a bring-your-own model provider layer. Select one with
`RISKRADAR_AGENT_PROVIDER`:

| Provider | Role | Who edits the repo? | Required env |
|---|---|---|---|
| `codex` (default) | Workspace editor | Codex CLI, in a disposable secret-scrubbed workspace | `CODEX_BIN`, `CODEX_ENABLED` |
| `openrouter` | Strict-JSON plan advisor | **RiskRadar** applies the plan | `RISKRADAR_LLM_API_KEY`, `RISKRADAR_AGENT_MODEL` |
| `openai-compatible` | Strict-JSON plan advisor | **RiskRadar** applies the plan | `RISKRADAR_LLM_BASE_URL`, `RISKRADAR_LLM_API_KEY`, `RISKRADAR_AGENT_MODEL` |
| `anthropic` | Strict-JSON plan advisor (Claude messages API) | **RiskRadar** applies the plan | `RISKRADAR_ANTHROPIC_API_KEY` (or `RISKRADAR_LLM_API_KEY`), `RISKRADAR_AGENT_MODEL` |
| `grok` | Strict-JSON plan advisor (xAI, OpenAI-compatible) | **RiskRadar** applies the plan | `RISKRADAR_GROK_API_KEY` (or `RISKRADAR_LLM_API_KEY`), `RISKRADAR_AGENT_MODEL` |
| `ollama` | Strict-JSON plan advisor (local) | **RiskRadar** applies the plan | `RISKRADAR_LLM_BASE_URL` (default `http://localhost:11434/v1`), `RISKRADAR_AGENT_MODEL` |
| `deterministic` | No model | **RiskRadar** updates to the OSV-known fixed version |, |

## Safety model

- Only Codex (the workspace editor) and RiskRadar's own deterministic applier
  mutate files. **The LLM advisors never edit the repo and never run commands.**
- LLM advisors must return a **strict JSON remediation plan only**:

  ```json
  {"action":"update_dependency","ecosystem":"npm","file":"package.json","packageName":"lodash","fromVersion":"4.17.20","toVersion":"4.17.21","summary":"..."}
  ```

- The plan is rejected if it: is not valid JSON; uses any action other than
  `update_dependency`; targets any file other than `package.json`; includes a
  command/script field; names a different package; proposes a downgrade, a
  major-version bump, or a version below the known fixed version.
- RiskRadar then applies the validated version bump itself, regenerates the
  lockfile, and runs `npm ci --ignore-scripts` / `npm test` / `npm run build`.
- If a provider is missing config, times out, errors, or proposes nothing safe,
  RiskRadar records the status honestly and falls back to the deterministic
  fixer. Provider completion is reported only when real file changes exist.

## Verification

```bash
pnpm verify:agent-provider          # selected provider + readiness (no secrets)
pnpm verify:openrouter-live         # real OpenRouter plan run, or honest skip
pnpm verify:openai-compatible-live  # real OpenAI-compatible run, or honest skip
pnpm verify:ollama-live             # real local Ollama run, or honest skip
```

Readiness (env var **names** only, never values) is also exposed at
`/api/health` (`agentProviders`) and on the Settings page.

> Tip: for Ollama, the default model is `qwen2.5-coder:7b` because that coder
> model returned the cleanest strict JSON in local verification. Override
> `RISKRADAR_AGENT_MODEL` if your machine has a different installed model.

## Env

```
RISKRADAR_AGENT_PROVIDER=codex | openrouter | openai-compatible | ollama | deterministic
RISKRADAR_AGENT_MODEL=<model>
RISKRADAR_LLM_BASE_URL=<url>
RISKRADAR_LLM_API_KEY=<key>
RISKRADAR_LLM_TIMEOUT_MS=120000
RISKRADAR_LLM_ALLOW_DIRECT_PATCH=false
```
