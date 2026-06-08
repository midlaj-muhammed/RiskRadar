# RiskRadar, Concept & Full Walkthrough

> **One-liner:** RiskRadar is a *Watch Commander for software supply-chain
> security*, it continuously watches your repos and AI-agent configs, finds the
> vulnerabilities that actually matter, drafts the fix with the AI model **you**
> choose, and never touches production without a signed human approval from your
> phone.

This document is the single source for building the **pitch deck** and the
**demo video**. It covers the problem, the idea, what we offer, why it's relevant
to 2026, who it helps, the solution and key features, the tech stack, the ideal
customer profile, and a complete walkthrough of everything that has been built, including an honest list of what is intentionally *not* done.

---

## 1. Problem statement

Modern software is assembled, not written. A typical app is **5–10% your code
and 90%+ other people's code**: npm/PyPI dependencies, transitive dependencies,
container base images, and now **AI agents and MCP servers** acting on the repo.
That creates three compounding problems:

1. **Alert overload, not insight.** Scanners (Dependabot, `npm audit`, OSV) emit
   hundreds of CVEs. Most teams can't tell which ones are *exploitable in their
   app* versus noise in an unused dev dependency. So nothing gets fixed, or the
   wrong things get fixed first.

2. **The fix is the hard part.** Knowing "lodash has a CVE" is easy. Producing a
   *safe, validated, reviewable* upgrade, bump the version, regenerate the
   lockfile, run the tests, prove nothing else changed, is slow manual toil.

3. **A new, unguarded attack surface in 2026: AI agents.** Coding agents,
   `mcp.json` servers, and auto-approve settings can read secrets, edit repos,
   and run commands. A misconfigured agent (`autoApprove: true`, an over-scoped
   token, a tool with shell access) is a supply-chain risk that *no traditional
   CVE scanner even looks at.*

On top of this, the obvious "just let AI auto-fix everything" answer is
**dangerous**: teams won't (and shouldn't) let a cloud LLM silently rewrite their
repo, leak secrets to a third party, or auto-merge to production.

**The gap:** there is no tool that ties together *triage that respects
reachability*, *agent/MCP-config security*, *bring-your-own-model remediation*,
and *human-in-the-loop approval with cryptographic provenance*, safely.

---

## 2. The idea

**RiskRadar is a command center that sits between your code and the act of
changing it.** It behaves like an on-call "watch commander":

- It **inventories** what you run, GitHub repos and allow-listed local folders,
  across **npm and PyPI**.
- It **scans** with *real* tools (OSV, Gitleaks, Trivy, Syft, Semgrep) plus
  built-in checks for **AI-agent/MCP misconfiguration**, secrets, typosquats and
  license risk, and **never fakes a green check**.
- It **triages** with a lightweight **reachability / VEX-lite** signal: is the
  vulnerable package *actually imported* in your source? If not, it's
  de-prioritized as likely-unused.
- It **remediates** using a **bring-your-own-model ladder**: your Codex
  subscription, a local Ollama model, a cloud provider, or a deterministic
  no-LLM path, with **automatic failover and explicit consent** before dropping
  to a lower-trust provider.
- It **validates** the fix (install, build, test), produces a **before/after
  lockfile diff** and an **SBOM diff**, and attaches a **signed provenance
  attestation** of exactly what changed and how it was verified.
- It **gates** every consequential action behind a **phone approval** (Telegram
  inline buttons), backed by HMAC-signed callbacks. **No auto-merge. No
  auto-deploy. No silent provider switching.**
- It is **agent-native**: every capability is exposed as **MCP tools**, so other
  AI agents can drive RiskRadar safely instead of touching the repo directly.

The thesis: **AI should plan the fix; a deterministic, audited, human-approved
pipeline should apply it.**

---

## 3. Everything RiskRadar offers (at a glance)

| Capability | What it does | Why it's different |
|---|---|---|
| **Multi-ecosystem SCA** | OSV-backed CVE scan for npm + PyPI, direct & transitive | Real OSV data + OSV-Scanner CLI, not a static list |
| **Reachability / VEX-lite** | Flags whether the vulnerable package is imported in *your* source | Cuts noise; de-prioritizes likely-unused/dev deps |
| **AI-agent / MCP security** | Scans `mcp.json`, agent configs for auto-approve, over-scoped tokens, shell tools | A 2026 attack surface no CVE scanner covers |
| **Scanner matrix** | Gitleaks (secrets), Trivy (containers), Syft (SBOM), Semgrep (SAST), typosquat/malicious-package, license | Orchestrates real tools; honest `tool_missing` when absent |
| **BYO model ladder** | Codex / OpenRouter / OpenAI-compatible / Anthropic / Grok / Ollama / deterministic | You own the model & data path; works fully offline |
| **Safe failover + consent** | Auto-fails over the provider chain, asks before lower-trust providers | No silent downgrade; secrets never sent to cloud models |
| **Validated remediation** | Scoped version bump → lockfile regen → install/build/test → patch/PR | Fix is proven, minimal, and reviewable |
| **Provenance attestation** | HMAC-signed statement of from→to, validation, files changed | SLSA-style, tamper-evident, verifiable in the PR |
| **Phone approval** | Telegram inline buttons (approve / reject / safer fix / rollback) | Human-in-the-loop with signed callbacks |
| **Continuous watch mode** | Re-scans on a schedule, alerts on *new* findings, dedupes | Never auto-patches; alert-only |
| **Audit receipts** | Hash-chained receipt for every action | Tamper-evident trail for compliance |
| **Durable layer (opt-in)** | Postgres system-of-record + Redis/BullMQ queue & schedule | Survives restarts; Docker one-command up |
| **MCP server** | ~25 tools exposing scan/triage/remediate/approve/rollback | Other agents drive RiskRadar, not your repo |
| **OpenClaw bridge** | Optional chat channel that drives RiskRadar via MCP (`/riskradar scan\|approve`) | Same gated tools as the dashboard; never edits the repo |

---

## 4. Relevance to 2026

RiskRadar is built directly on the security themes dominating 2025–2026:

- **The AI-agent attack surface is now real.** With coding agents and MCP servers
  everywhere, *agent configuration* is a first-class supply-chain risk. RiskRadar
  scans `mcp.json`/agent configs for auto-approve, over-permissive tokens, and
  dangerous tools, something traditional scanners do not do.
- **Reachability / VEX is the industry's answer to alert fatigue.** Vendors are
  racing to add "is this CVE actually exploitable here?" RiskRadar ships a
  lightweight, honest **VEX-lite** signal in the same spirit.
- **Provenance & SLSA are mainstream requirements.** Buyers increasingly demand
  signed evidence of *how* an artifact/change was produced. RiskRadar signs each
  remediation with a verifiable attestation.
- **Agentic remediation with human oversight** is the accepted safe pattern:
  let the model propose, keep a human in the loop, keep an audit trail.
  RiskRadar is architected around exactly this.
- **Bring-your-own / local models** matter for data-sensitive teams. RiskRadar
  runs end-to-end on a **local Ollama** model or your **Codex subscription**:   no data leaves your machine unless you opt in.
- **AIBOM / SBOM** expectations are rising. RiskRadar generates a Syft CycloneDX
  SBOM and a before/after diff for each fix.

In short: RiskRadar isn't chasing a trend, it sits at the intersection of the
five biggest ones.

---

## 5. Who does this help? (ICP / target audience)

**Primary ICP, the "security-aware engineering team without a security team":**

- **Seed → Series-B startups (10–150 engineers)** shipping fast on npm/PyPI, with
  no dedicated AppSec hire. They feel CVE pain but can't staff triage.
- **Platform / DevEx engineers** who own CI/CD and dependency hygiene for many
  repos and want one command center instead of per-repo Dependabot noise.
- **Teams adopting AI coding agents / MCP** who suddenly have agent configs and
  auto-approve settings to secure, and no tool that even looks at them.

**Secondary:**

- **Data-sensitive / regulated teams** (fintech, health, gov-adjacent) who
  **cannot** send code to a cloud LLM, RiskRadar's local Ollama + deterministic
  paths and audit receipts fit their constraints.
- **Open-source maintainers** who want validated, reviewable dependency-bump PRs
  without babysitting every advisory.
- **Solo developers / indie hackers** who want "fix my CVEs safely" from their
  phone.

**Buyer vs. user:** the *user* is a developer/platform engineer; the *buyer* is
an eng lead / CTO who needs the audit trail and the "no auto-merge / no data
leak" guarantees to say yes.

**Why they choose RiskRadar:** it's the only option that is *safe by default*
(human approval, no silent actions, secrets never leave), *honest* (no fake
green), *model-agnostic* (BYO/local), and *agent-native* (MCP).

---

## 6. Proposed solution & key features (detailed)

### 6.1 Inventory & scan (real, never faked)
- Sources: **GitHub repos** (cloned to an ephemeral, secret-scrubbed workspace)
  and **allow-listed local folders** (path-traversal-guarded).
- Ecosystems: **npm + PyPI**, direct and transitive, lockfile-aware confidence.
- Scanners orchestrated: **OSV** (API + OSV-Scanner CLI), **Gitleaks** (secrets),
  **Trivy** (container images), **Syft** (SBOM), **Semgrep** (SAST), plus
  **built-in** checks: AI-agent/MCP config, CI hardening, lightweight secrets,
  malicious/typosquat packages, license policy.
- **Honesty guarantee:** a missing tool shows `tool_missing` / `not_configured`,
  never a fake pass. Risk is enriched with **EPSS** and **CISA KEV** when
  available; missing data is labeled, not guessed.

### 6.2 Reachability / VEX-lite triage *(new)*
- After findings are built, RiskRadar walks first-party source **once** and
  records which top-level packages are actually imported (npm `require/import`,
  Python `import/from`).
- Each finding is tagged:
  - **`imported`** → treat as reachable (prioritize).
  - **`not_imported`** (direct npm dep never imported) → likely unused/dev-only,
    **de-prioritize**.
  - **`indirect`** (transitive) → reached via a parent, not first-party.
  - **`unknown`** (e.g. PyPI where the install name ≠ import name) → honest "can't
    tell," never a false claim.
- Surfaced in the dashboard's **Reachability** column and in the PR body.
- *Deliberately conservative:* this is an import-presence signal, **not** full
  call-graph analysis, and the UI says so.

### 6.3 Bring-your-own model ladder + safe failover
- Providers: **Codex** (the only model allowed to edit the repo, via your
  subscription login), **OpenRouter / OpenAI-compatible / Anthropic / Grok**
  (strict-JSON *plan advisors*, RiskRadar applies the change, the model never
  touches the repo), **Ollama** (local), and **deterministic** (no model; bump to
  the OSV-known fixed version).
- **Failover chain** with a readiness cache; on failure it advances the chain.
- **Consent before lower-trust:** dropping from Codex → cloud → local requires an
  explicit Telegram consent (configurable `ask` / `automatic` / `disabled`).
- **Hard safety rails:** raw secret findings are **never** sent to cloud models;
  non-Codex providers **cannot** mutate the repo; nothing switches silently.

### 6.4 Validated, minimal remediation
- Scoped edit (`package.json`/`requirements.txt`) → lockfile regeneration →
  **install / build / test** in a sandbox (install lifecycle scripts off by
  default).
- Produces a **before/after lockfile diff** for the target package and a **Syft
  SBOM diff**.
- Blocks the PR/patch if validation fails or if **secret-like/forbidden files**
  were touched.

### 6.5 Provenance attestation on the fix *(new)*
- Each successful remediation emits a **canonical, HMAC-signed statement**:
  `{package, ecosystem, fromVersion→toVersion, fixStrategy, validation result,
  CVE/OSV ids, changed files, remediationJobId, agent, timestamp}`.
- Signed with `RISKRADAR_ATTESTATION_SECRET` (falls back to
  `APPROVAL_HMAC_SECRET`); if no secret is set it returns an **honest unsigned**
  statement (never a fake signature).
- The signed line + JSON go into the **PR body** and the **audit receipt**, and
  can be re-verified with `verifyAttestation(statement, signature)`: SLSA-style,
  tamper-evident provenance.

### 6.6 Human-in-the-loop approval (phone)
- **Telegram inline buttons**: Approve / Reject / Retry safer fix / Rollback, via
  a webhook with a shared secret; callbacks are **HMAC-signed and expiring**;
  chat IDs are allow-listed and hashed in storage.
- **No auto-merge, no auto-deploy**: ever. Rollback closes the draft PR + deletes
  the branch, or reverse-applies the local patch.

### 6.7 Continuous watch mode
- Scheduled re-scans, **new-finding** alerts with dedupe, optional quiet hours.
- **Never auto-patches**: watch mode is alert-only by design.

### 6.8 Durable layer (opt-in, Docker)
- **Postgres** write-through JSONB system-of-record with **hydrate-after-file-loss**.
- **Redis/BullMQ** durable queue + repeatable watch schedule that survives
  restarts. One command: `docker compose up -d`.

### 6.9 Audit, MCP, OpenClaw, and security model
- **Hash-chained audit receipts** for every action (tamper-evident).
- **MCP server** exposes ~25 tools (list/scan/triage/remediate/validate/PR/
  approve/rollback/readiness/coverage/watch) so *other agents and IDEs drive
  RiskRadar* rather than the repo.
- **OpenClaw bridge (optional):** a chat front-end that connects to the same MCP
  server, giving commands like `/riskradar status`, `/riskradar scan`,
  `/riskradar affected`, `/riskradar approve <id>`. It uses the identical gated
  tools, it can request scans/remediation but **cannot auto-merge, auto-deploy,
  or edit the repo**, and only reports success when actually configured
  (`OPENCLAW_ENABLED=true` + CLI installed).
- **Secrets hygiene:** redaction everywhere; secret-manager file indirection
  (`RISKRADAR_SECRETS_FILE`); optional dashboard/API token; signed plugin
  registry (HMAC).
- **Deployment verification (Vercel):** can ping a preview/prod URL and report
  live/status, it **never triggers a deploy**.

---

## 7. Tools / tech stack

**Language & runtime:** TypeScript, Node.js, **pnpm monorepo**.

**Monorepo layout:**
- `packages/core`: all domain logic (scan, triage, remediation, attestation,
  providers, watch, audit, persistence). Pure, unit-tested.
- `apps/web`: **Next.js 16** dashboard + API routes + auth middleware.
- `apps/worker`: local/queue worker (scan-all, watch).
- `apps/mcp`: stdio **MCP server** (Model Context Protocol).

**Security tooling integrated (real CLIs):** OSV / OSV-Scanner, Gitleaks, Trivy,
Syft, Semgrep.

**AI / models:** OpenAI **Codex** CLI (subscription login), Vercel AI SDK / AI
Gateway adapters, **Ollama** (local), and OpenAI-compatible / OpenRouter /
Anthropic / Grok HTTP advisors. Deterministic no-LLM fallback.

**Intelligence feeds:** OSV.dev, EPSS (FIRST), CISA KEV, OpenSSF malicious
packages.

**Persistence & queue:** file-backed JSON store by default; **Postgres 16**
(JSONB) + **Redis 7 / BullMQ** via **Docker Compose**, opt-in.

**Notifications / approval:** **Telegram Bot API** (inline buttons + webhook),
tunneled with cloudflared for local demos.

**Crypto / integrity:** Node `crypto` HMAC-SHA256 for approval callbacks,
provenance attestations, and signed plugin manifests; hash-chained audit receipts.

**Testing & QA:** **Vitest** (110 unit/integration tests), plus a large suite of
`verify:*` / `demo:*` / `check:*` scripts and a self-audit (`audit:repo`).

**Platform notes:** Windows-first spawn safety (absolute `.exe` vs `.cmd` vs bare
names), runs on Windows/macOS/Linux/WSL.

### 7.1 Integrations (complete map)

Every integration is **honest**: it reports `configured` / `available` only when
the credential or binary is actually present, otherwise `not_configured`,
`unavailable`, or `tool_missing`. Nothing is faked. This is the full surface
(matches the dashboard's integration-health panel):

| Integration | Type | Role in RiskRadar | Default state |
|---|---|---|---|
| **GitHub** | Source + PR | Clone repos to ephemeral secret-scrubbed workspace; open **draft** PRs (token or GitHub App) | `not_configured` until `GITHUB_TOKEN`/App set |
| **Local folders** | Source | Scan allow-listed local paths (traversal-guarded) | available when `RISKRADAR_LOCAL_ROOTS` set |
| **OSV.dev API** | Vuln intel | Primary CVE source for npm + PyPI | configured (public API) |
| **OSV-Scanner CLI** | Scanner | Lockfile-aware SCA, multi-ecosystem | `tool_missing` until installed |
| **EPSS (FIRST)** | Risk intel | Exploit-probability score per CVE | configured (public API) |
| **CISA KEV** | Risk intel | Known-exploited flag + ransomware/due-date | configured (public feed) |
| **NVD / GHSA** | Enrichment | Optional severity/details enrichment | optional (`NVD_API_KEY`, GHSA URL) |
| **OpenSSF malicious-packages** | Scanner data | Malicious/typosquat package matching | optional dir |
| **Gitleaks** | Scanner | Secret detection (findings redacted) | `tool_missing` until installed |
| **Trivy** | Scanner | Container-image CVEs + license scan | `tool_missing` until installed |
| **Syft** | Scanner | CycloneDX **SBOM** generation + diff | `tool_missing` until installed |
| **Semgrep** | Scanner | SAST (not on native Windows → WSL/Docker) | `tool_missing` |
| **OpenAI Codex CLI** | Remediation model | The **only** model allowed to edit the repo (subscription login) | `available` when `codex` installed + `CODEX_ENABLED` |
| **OpenAI SDK** | Model | API-key remediation path | `not_configured` until `OPENAI_API_KEY` |
| **Vercel AI SDK / AI Gateway** | Model | Gateway-routed plan advisor | `not_configured` until `AI_GATEWAY_API_KEY` |
| **Ollama** | Local model | Fully offline plan advisor (verified live) | available when daemon running |
| **OpenRouter / OpenAI-compatible / Anthropic / Grok** | Cloud advisors | Strict-JSON plan advisors (never edit repo) | **intentionally `not_configured`** |
| **Telegram Bot API** | Approval channel | Inline-button approvals/consent + webhook (HMAC) | `not_configured` until bot token/chat set |
| **OpenClaw** | Approval / chat bridge | Alternate channel that drives RiskRadar **through the MCP server** (`/riskradar status\|scan\|affected\|approve`); respects all approval/consent gates | optional, `OPENCLAW_ENABLED=true` + CLI |
| **MCP server** | Agent interface | ~25 tools so other agents/IDEs orchestrate RiskRadar (not the repo) | enabled (`RISKRADAR_MCP_ENABLED`) |
| **Vercel (deployment)** | Verify only | Pings a preview/prod URL, detects Vercel, reports live/status, **never deploys** | optional URL |
| **Postgres 16** | Persistence | Write-through JSONB system-of-record + hydrate-on-restart (Docker) | opt-in `RISKRADAR_PERSIST_POSTGRES` |
| **Redis 7 / BullMQ** | Queue/scheduler | Durable jobs + repeatable watch schedule (Docker) | opt-in `RISKRADAR_QUEUE_MODE=redis` |
| **Secret-manager file** | Secrets | Fills unset keys from Docker/K8s mount or Vault file sink | optional `RISKRADAR_SECRETS_FILE` |
| **Signed plugin registry** | Extensibility | HMAC-signed plugin manifests; unsigned/tampered rejected | optional signing secret |
| **cloudflared** | Demo infra | Tunnels the Telegram webhook for local demos | dev-only |

**Trust tiers (who may touch the repo):** only **Codex** and RiskRadar's own
deterministic applier can mutate files. **All cloud/local advisors and OpenClaw
plan or orchestrate only**: they never write to your repo, and raw secret
findings are never sent to cloud models.

---

## 8. Architecture (for the deck's "how it works" slide)

```
                 ┌───────────────────────────────────────────────────────┐
                 │                  RiskRadar core (TS)                   │
  GitHub repo ─► │  inventory → SCAN (OSV + scanner matrix + agent/MCP)   │
  Local folder ► │      │                                                 │
                 │      ▼                                                  │
                 │  REACHABILITY / VEX-lite  (imported? de-prioritize)     │
                 │      │                                                  │
                 │      ▼                                                  │
                 │  RISK (EPSS + CISA KEV + blast radius)                  │
                 │      │                                                  │
                 │      ▼                                                  │
                 │  REMEDIATE  ── BYO model ladder ──► Codex / Ollama /    │
                 │      │           (failover + consent)   cloud / det.    │
                 │      ▼                                                  │
                 │  VALIDATE (install/build/test) → lockfile + SBOM diff   │
                 │      │                                                  │
                 │      ▼                                                  │
                 │  ATTEST (HMAC-signed provenance)                        │
                 │      │                                                  │
                 │      ▼                                                  │
                 │  APPROVAL (Telegram, signed) ──► PR / patch (NO merge)  │
                 │      │                                                  │
                 │      ▼                                                  │
                 │  AUDIT (hash-chained receipts)                          │
                 └───────────────────────────────────────────────────────┘
   Surfaces:  Next.js dashboard  •  MCP tools (agents/IDEs)  •  Telegram phone  •  OpenClaw chat
   Durable:   JSON file (default)  •  Postgres + Redis/BullMQ (opt-in, Docker)
```

---

## 9. Full walkthrough of everything built (the demo narrative)

This is the order to **show in the video**. Each step has a real command.

1. **Boot the command center.** `pnpm dev` → dashboard at
   `http://127.0.0.1:3000`. Show projects, threat radar, audit log.
2. **Scan a real project.** Add a GitHub repo or a local folder
   (`RISKRADAR_LOCAL_ROOTS`), run `pnpm scan:fixture` / `scan:project-full`.
   Show real OSV findings for npm **and** PyPI.
3. **Triage with reachability.** On the **Findings** page, point to the new
   **Reachability** column: `🎯 reachable` vs `💤 likely unused` vs
   `🔗 transitive`. Explain VEX-lite cuts the noise.
4. **Show the agent/MCP security angle.** Point out agent-config warnings
   (auto-approve / over-scoped token), the 2026 differentiator.
5. **Pick your model.** Show the provider ladder. Run the deterministic path live
   (`demo:provider-failover`), then mention Codex/Ollama. Emphasize *consent
   before lower-trust* and *secrets never leave*.
6. **Remediate + validate.** Trigger a fix → scoped bump → lockfile regen →
   install/build/test → **lockfile diff + SBOM diff** (`verify:sbom`).
7. **Provenance.** Open the draft PR body: show the **signed attestation** block
   (from→to, validation, files, signature) and explain it's verifiable.
8. **Approve from your phone.** Telegram inline buttons
   (`demo:telegram-buttons`); tap **Approve**. Show that it's HMAC-signed and that
   **nothing auto-merges**. Optionally demo **Rollback**.
9. **Continuous watch.** `demo:watch`: scheduled re-scan, new-finding alert,
   dedupe, **no auto-patch**.
10. **Agent-native.** `pnpm mcp:dev`: show the MCP tools an external agent or
    IDE can call (and the optional **OpenClaw** chat bridge: `/riskradar scan`,
    `/riskradar approve`). The point: agents orchestrate RiskRadar, not your repo.
11. **Durability (optional).** `docker compose up -d` + `verify:postgres` /
    `verify:queue`: survives restarts.
12. **Honesty & audit.** Show `not_configured`/`tool_missing` statuses and the
    hash-chained audit receipts. Close on: *"no fake green, no silent action,
    no data leak."*

**Verification you can cite on a slide:** `pnpm test` (110 passing),
`pnpm check:full`, `audit:repo`, and the `verify:*` matrix.

---

## 10. What's intentionally NOT done (honesty slide)

Being explicit here *increases* credibility with technical judges:

- **Cloud LLM providers** (OpenRouter/OpenAI-compatible/Anthropic/Grok) ship
  wired and unit-tested but left **`not_configured`** by choice; the **Codex** and
  **local Ollama** paths are verified live.
- **Semgrep** doesn't run on native Windows (use WSL/Docker); shown as
  `tool_missing`, runner/parser proven with fixtures.
- **Reachability is import-presence, not call-graph.** Conservative by design.
- **Python validation** (pip install/test) is skipped in-sandbox; the
  requirements.txt patch is produced and reviewed.
- **Go/Maven/Cargo/Composer** are *scanned* (OSV) but not yet *remediated*.
- **Postgres** is a write-through durable store + hydration, not a full
  multi-instance async DB; single-machine model.
- Not production-grade, **solid and honest**, by design for the hackathon.

**Safety guarantees (features, not gaps):** no auto-merge, no auto-deploy, no
silent provider switching, no secrets in repo/API/logs; only Codex and
RiskRadar's own applier mutate files, advisor LLMs only plan.

---

## 11. Suggested pitch-deck outline (map to this doc)

1. **Title**: RiskRadar: the Watch Commander for supply-chain security. (§1 one-liner)
2. **Problem**: assembled software + alert overload + the new AI-agent surface. (§1)
3. **Why now / 2026**: agents, VEX, SLSA, BYO/local models, AIBOM. (§4)
4. **The idea**: AI plans, an audited human-approved pipeline applies. (§2)
5. **Demo**: the live walkthrough. (§9)
6. **Key features**: reachability, BYO ladder, attestation, phone approval. (§6)
7. **Architecture**: the one diagram. (§8)
8. **Tech stack**: monorepo + real scanners + MCP. (§7)
9. **Who it's for**: ICP + buyer/user split. (§5)
10. **Honesty & safety**: what's not done + the guarantees. (§10)
11. **Ask / vision**: where it goes next (call-graph reachability, more
    ecosystems, hosted mode).

---

## 12. Taglines you can drop into slides

- *"AI plans the fix. A signed, human-approved pipeline applies it."*
- *"No fake green. No silent action. No data leak."*
- *"Find what's reachable. Fix it safely. Prove it with a signature."*
- *"Your repos and your AI agents, one command center."*
- *"Bring your own model. Even an offline one."*
