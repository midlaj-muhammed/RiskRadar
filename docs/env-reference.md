# Environment Reference

Every environment variable RiskRadar actually reads, grouped by feature. All
values in `.env.example` are placeholders, **never commit a real `.env`**
(`.gitignore` excludes it). Secrets are marked 🔒; safe-to-share placeholders are
marked 🟢.

> Naming note: the implemented LLM provider keys are RiskRadar-prefixed and
> shared across OpenAI-compatible providers. OpenRouter and the generic
> OpenAI-compatible provider use `RISKRADAR_LLM_API_KEY` + `RISKRADAR_LLM_BASE_URL`;
> Ollama uses `RISKRADAR_LLM_BASE_URL` (default `http://localhost:11434/v1`) +
> `RISKRADAR_AGENT_MODEL`. Anthropic and Grok have dedicated keys. There are no
> `OPENROUTER_API_KEY` / `OLLAMA_BASE_URL` style keys, those names are not read.

## Core app
| Key | Secret | Default | Feature | If missing |
|---|---|---|---|---|
| `RISKRADAR_DATA_FILE` | 🟢 | `.riskradar/riskradar.db.json` | Local JSON state store | Uses default path |
| `RISKRADAR_LOG_DIR` | 🟢 | `.riskradar/logs` | Validation/command logs | Uses default path |
| `RISKRADAR_WORKSPACE_DIR` | 🟢 | `.riskradar/workspaces` | Disposable remediation workspaces | Uses default path |
| `APP_PUBLIC_URL` | 🟢 | `http://localhost:3000` | OpenRouter `HTTP-Referer` header | Uses a default referer |
| `NODE_ENV` | 🟢 | `development` | Runtime mode | development |

## GitHub
| Key | Secret | Default | Feature | If missing |
|---|---|---|---|---|
| `GITHUB_TOKEN` | 🔒 |, | Repo validation, scan clone, draft PR create/close, branch delete | GitHub features error honestly (`not_configured`) |
| `RISKRADAR_TEST_REPO` | 🟢 |, | Safe demo repo for live verification (must contain `riskradar-test/-demo`) | Live GitHub scripts refuse to run |

## Local folders
| Key | Secret | Default | Feature | If missing |
|---|---|---|---|---|
| `RISKRADAR_LOCAL_ROOTS` | 🟢 |, | Allowlisted roots for local folder scanning | Local projects can't be added (path rejected) |
| `RISKRADAR_APPLY_LOCAL_PATCH_ON_APPROVAL` | 🟢 | `false` | Apply local patch to the folder on approval | Patch is created but not applied |

## Telegram
| Key | Secret | Default | Feature | If missing |
|---|---|---|---|---|
| `TELEGRAM_BOT_TOKEN` | 🔒 |, | Sending approval/consent/watch messages | Telegram send disabled (dashboard-only) |
| `TELEGRAM_CHAT_ID` / `TELEGRAM_ALLOWED_CHAT_IDS` | 🔒 |, | Allowlisted chat(s) | No recipient; sends skipped, webhook taps rejected |
| `TELEGRAM_WEBHOOK_SECRET` | 🔒 |, | Authenticates the inbound webhook (`X-Telegram-Bot-Api-Secret-Token`) | Webhook validation is skipped (set it in production) |
| `APPROVAL_SIGNING_SECRET` / `APPROVAL_HMAC_SECRET` | 🔒 |, | HMAC for legacy signed approval tokens | Token approvals can't be signed/verified |

## Codex
| Key | Secret | Default | Feature | If missing |
|---|---|---|---|---|
| `CODEX_BIN` | 🟢 | `codex` | Codex CLI binary/path | Resolves `codex` on PATH |
| `CODEX_ENABLED` | 🟢 | `true` | Toggle Codex provider | `false` → Codex reported unavailable |
| `CODEX_SANDBOX_MODE` | 🟢 | `workspace-write` | Documented sandbox mode | workspace-write enforced via flags |
| `CODEX_TIMEOUT_MS` | 🟢 | `300000` | Codex exec timeout | 10 min default; `verify:codex-live` floors at 300000 |

## Provider layer (BYO model)
| Key | Secret | Default | Feature | If missing |
|---|---|---|---|---|
| `RISKRADAR_AGENT_PROVIDER` | 🟢 | `codex` | Selected remediation provider | Defaults to codex |
| `RISKRADAR_AGENT_MODEL` | 🟢 | per-provider | Model id for the active LLM provider | Provider default model |
| `RISKRADAR_LLM_BASE_URL` | 🟢 | provider default | Base URL for openrouter/openai-compatible/ollama | openai-compatible requires it; others have defaults |
| `RISKRADAR_LLM_API_KEY` | 🔒 |, | Key for openrouter/openai-compatible (and fallback for grok/anthropic) | Those providers report `not_configured` (no network call) |
| `RISKRADAR_LLM_TIMEOUT_MS` | 🟢 | `120000` | LLM request timeout | 120s |
| `RISKRADAR_LLM_ALLOW_DIRECT_PATCH` | 🟢 | `false` | Reserved switch (RiskRadar still applies changes itself) | false |
| `RISKRADAR_ANTHROPIC_API_KEY` | 🔒 | (falls back to `RISKRADAR_LLM_API_KEY`) | Anthropic Claude provider | `not_configured` |
| `RISKRADAR_ANTHROPIC_BASE_URL` | 🟢 | `https://api.anthropic.com` | Anthropic endpoint | default |
| `RISKRADAR_ANTHROPIC_VERSION` | 🟢 | `2023-06-01` | Anthropic API version header | default |
| `RISKRADAR_GROK_API_KEY` | 🔒 | (falls back to `RISKRADAR_LLM_API_KEY`) | Grok/xAI provider | `not_configured` |
| `RISKRADAR_GROK_BASE_URL` | 🟢 | `https://api.x.ai/v1` | Grok endpoint | default |

## Provider failover ladder
| Key | Secret | Default | Feature |
|---|---|---|---|
| `RISKRADAR_PROVIDER_FAILOVER_MODE` | 🟢 | `ask` | `ask`/`automatic`/`disabled` |
| `RISKRADAR_PROVIDER_CHAIN` | 🟢 | `codex,openrouter,anthropic,grok,openai-compatible,ollama,deterministic` | Ordered chain |
| `RISKRADAR_ALLOW_CLOUD_MODEL_FAILOVER` | 🟢 | `true` | Cloud→cloud auto-failover |
| `RISKRADAR_ALLOW_LOCAL_MODEL_FAILOVER` | 🟢 | `false` | Use local model without consent |
| `RISKRADAR_REQUIRE_CONSENT_FOR_LOWER_TRUST_PROVIDER` | 🟢 | `true` | Consent before local/deterministic in ask mode |
| `RISKRADAR_FAST_FAILOVER` | 🟢 | `true` | Fast-failover behaviour |
| `RISKRADAR_PROVIDER_CHAIN_MAX_ATTEMPTS` | 🟢 | `3` | Max provider attempts |
| `RISKRADAR_PROVIDER_READINESS_TIMEOUT_MS` | 🟢 | `3000` | Readiness probe timeout |
| `RISKRADAR_PROVIDER_ATTEMPT_TIMEOUT_MS` | 🟢 | `30000` | Per-attempt timeout |
| `RISKRADAR_PROVIDER_READINESS_CACHE_TTL_MS` | 🟢 | `600000` | Readiness cache TTL |

## Watch mode
| Key | Secret | Default | Feature |
|---|---|---|---|
| `RISKRADAR_WATCH_ENABLED` | 🟢 | `false` | Continuous watch loop (off by default) |
| `RISKRADAR_WATCH_INTERVAL_MINUTES` | 🟢 | `60` | Scan interval |
| `RISKRADAR_WATCH_TELEGRAM_ALERTS` | 🟢 | `true` | Telegram alerts on new findings |
| `RISKRADAR_QUIET_HOURS` | 🟢 |, | e.g. `23:00-07:00`; suppresses non-critical alerts |

## Scanners
`RISKRADAR_SCANNER_<TOOL>_ENABLED` (toggle) and `_PATH` (binary) for `OSV`,
`GITLEAKS`, `SEMGREP`, `TRIVY`, `SYFT`. Plus `RISKRADAR_SCANNER_TIMEOUT_MS`
(default `120000`), `RISKRADAR_MALICIOUS_PACKAGES_DIR` (OpenSSF data dir →
enables "malicious" labels), `RISKRADAR_LICENSE_POLICY_PATH` (allowed/review/
blocked policy). Missing tool → `tool_missing` with install hint (never fake).
SBOM (Syft) is `disabled` by default.

## Vulnerability intelligence
`OSV_API_URL` (default OSV querybatch), `NVD_API_URL`/`NVD_API_KEY`,
`GHSA_API_URL`, `EPSS_API_URL`, `CISA_KEV_URL`. All best-effort enrichment;
missing/erroring sources are recorded separately from "not found".

## Deployment / Vercel (optional)
`VERCEL_TOKEN` 🔒, `VERCEL_TEAM_ID`, `VERCEL_OIDC_TOKEN` 🔒, `AI_GATEWAY_API_KEY` 🔒,
`AI_GATEWAY_MODEL`. Local `.vercel/project.json` mapping works without a token.

## OpenAI SDK / OpenClaw / MCP / SBOM
`OPENAI_API_KEY` 🔒 + `OPENAI_MODEL` (plan-only adapter), `OPENCLAW_BIN` +
`OPENCLAW_ENABLED` (optional bridge), `RISKRADAR_MCP_ENABLED`, `SYFT_BIN`,
`CYCLONEDX_NPM_BIN`.

## Safety posture
`RISKRADAR_ALLOW_AUTO_MERGE=false`, `RISKRADAR_ALLOW_PROD_DEPLOY=false`
(documented posture, RiskRadar never merges/deploys regardless),
`RISKRADAR_RETAIN_WORKSPACES=false`, `RISKRADAR_COMMAND_TIMEOUT_MS=120000`,
`RISKRADAR_ALLOW_VALIDATION_SCRIPTS=false` (npm lifecycle scripts ignored during
validation unless explicitly enabled).

## Test/advanced flags
`RISKRADAR_DISABLE_OSV_SCANNER` (force OSV-API path in tests),
`RISKRADAR_SMOKE_BASE_URL` (smoke target), `RISKRADAR_QUEUE_MODE`/
`RISKRADAR_WORKER_MODE` (`local` inline mode), `DATABASE_URL`/`REDIS_URL`
(reserved for future adapters, not used by the local inline path).
