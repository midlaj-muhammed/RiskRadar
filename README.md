<div align="center">
  <h1>RiskRadar</h1>
  <p><strong>Watch Commander for Supply-Chain Security</strong></p>
  <p>
    <a href="https://www.npmjs.com/package/riskradar-cli"><img src="https://img.shields.io/npm/v/riskradar-cli" alt="npm"></a>
    <a href="https://github.com/midlaj-muhammed/RiskRadar.git"><img src="https://img.shields.io/github/license/midlaj-muhammed/RiskRadar" alt="License"></a>
    <a href="https://tryriskradar.vercel.app"><img src="https://img.shields.io/badge/demo-live-brightgreen" alt="Demo"></a>
  </p>
  <p>
    <a href="https://tryriskradar.vercel.app">Live Demo</a> ·
    <a href="#quick-start">Quick Start</a> ·
    <a href="#cli">CLI</a> ·
    <a href="docs/CONCEPT.md">Docs</a>
  </p>
</div>

---

RiskRadar inventories GitHub repos and local folders, scans dependencies with real OSV data, enriches risk with EPSS/CISA KEV, and gates remediation through approval workflows.

Everything runs live — unconfigured integrations show as `not_configured` so the dashboard always reflects reality.

## CLI

Scan any Node.js or Python project in one command:

```bash
npx riskradar-cli scan
npx riskradar-cli scan ./my-app --fail-on high --json
```

Each finding is tagged with reachability (VEX-lite) so you fix what's actually imported first.

## Quick Start

```bash
pnpm install
cp .env.example .env
pnpm dev
```

Open **http://127.0.0.1:3000**.

To scan a local folder, set `RISKRADAR_LOCAL_ROOTS` in `.env` to the parent directory:

```bash
RISKRADAR_LOCAL_ROOTS="/path/to/projects"
pnpm scan:fixture
```

## Commands

| Command | Description |
|---------|-------------|
| `pnpm dev` | Next.js dashboard + API |
| `pnpm worker:dev` | Local worker (supports `--scan-all`) |
| `pnpm mcp:dev` | MCP stdio server |
| `pnpm cli:bundle` | Build CLI bundle |
| `pnpm test` | Run tests |
| `pnpm build` | Build all packages |
| `pnpm typecheck` | Type-check all packages |
| `pnpm verify:local-e2e` | Local end-to-end verification |
| `pnpm smoke:app` | Smoke-test the app |
| `pnpm check:full` | Full validation suite |

## Features

### Scanning & Risk

- Real OSV API dependency scanning (npm + PyPI)
- Reachability triage (VEX-lite) — prioritize imported deps
- EPSS / CISA KEV enrichment
- NVD and GitHub Advisory lookups
- Risk scoring with missing-data indicators
- SBOM generation via Syft
- Agent supply-chain shield (Codex, MCP, GitHub Actions)

### Remediation

- Deterministic npm remediation with patch artifacts
- Codex CLI remediation in disposable workspaces
- BYO model provider (Codex, OpenRouter, OpenAI, Ollama)
- Rollback support for applied patches

### Approvals & Audit

- Blast radius analysis per finding
- Telegram approval with HMAC verification
- Audit receipts with hash chaining
- GitHub PR creation for fixes

### Dashboard

- Next.js dashboard with live metrics
- Threat radar, watch mode, scanner management
- Provider failover and consent flows

## Environment

| Variable | Required For |
|----------|-------------|
| `RISKRADAR_LOCAL_ROOTS` | Local folder scanning |
| `GITHUB_TOKEN` | GitHub repo validation and PRs |
| `TELEGRAM_BOT_TOKEN` | Telegram approvals |
| `TELEGRAM_ALLOWED_CHAT_IDS` | Telegram approvals |
| `APPROVAL_HMAC_SECRET` | Approval webhook security |
| `CODEX_BIN` / `CODEX_ENABLED` | Codex remediation |
| `OPENAI_API_KEY` | OpenAI plan adapter |
| `SYFT_BIN` | SBOM generation |
| `VERCEL_TOKEN` | Vercel deployment API |

## Verification Status

| Status | Details |
|--------|---------|
| Verified locally | Fixture scan, risk score, remediation, audit, dashboard smoke tests |
| Needs credentials | GitHub scan, PR creation, Telegram send, live Codex |
| Partial | Redis/Postgres persistence, OSV-Scanner CLI, deployment URL verification |

## Documentation

| Resource | Description |
|----------|-------------|
| [docs/CONCEPT.md](docs/CONCEPT.md) | Product walkthrough |
| [docs/architecture.md](docs/architecture.md) | System architecture |
| [docs/security-model.md](docs/security-model.md) | Security model |
| [docs/scanners.md](docs/scanners.md) | Scanner plugins |
| [docs/model-providers.md](docs/model-providers.md) | Provider configuration |
| [docs/mcp-server.md](docs/mcp-server.md) | MCP server reference |
| [docs/telegram-approval.md](docs/telegram-approval.md) | Telegram integration |
| [docs/watch-mode.md](docs/watch-mode.md) | Watch mode |
| [docs/codex-integration.md](docs/codex-integration.md) | Codex integration |
| [docs/env-reference.md](docs/env-reference.md) | Environment reference |

## Project Structure

```
apps/
  web/          Next.js dashboard + API
  worker/       Background worker
  mcp/          MCP server
  cli/          CLI scanner
packages/
  core/         Scanning, risk, remediation, integrations
scripts/        Verification and demo scripts
tests/fixtures/ Disposable vulnerable fixtures
docs/           Topic guides
plugins/        Scanner plugins
```

---

<div align="center">
  <a href="https://tryriskradar.vercel.app">Live Demo</a> ·
  <a href="docs/CONCEPT.md">Docs</a> ·
  <a href="LICENSE">MIT License</a>
</div>
