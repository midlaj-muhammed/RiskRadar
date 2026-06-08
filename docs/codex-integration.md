# Codex Integration

RiskRadar detects the Codex CLI with `CODEX_BIN` and `CODEX_ENABLED`.

Implemented:

- Codex availability health.
- Strict remediation prompt.
- `riskradar-context.json` writer.
- `codex_not_executed` remediation state when Codex is unavailable.
- Secret redaction before context/log storage.
- Disposable workspace copy/clone.
- Codex CLI execution through `codex exec` with `--sandbox workspace-write`, ephemeral execution, non-interactive approval config, and `CODEX_TIMEOUT_MS`.
- Changed-file capture.
- Validation before PR/patch.
- GitHub draft PR or local patch artifact after validation.

The worker execution path runs in a disposable workspace and uses (prompt via stdin, never as an argument):

```bash
codex exec --cd <workspace> --sandbox workspace-write --ephemeral --skip-git-repo-check -c approval_policy="never" -
```

RiskRadar excludes `.env`, `.env.*`, private keys, token files, npm credential files, and secret-like config before creating a Codex workspace. The Codex child process receives a secret-scrubbed environment (only `PATH`, the OS runtime vars, and `~/.codex` auth via `USERPROFILE`/`CODEX_HOME`: never GitHub/Telegram/approval secrets). It does not claim Codex changed files unless the command really ran.

## Diagnosing the CLI

`pnpm verify:codex-cli` runs three safe checks and reports exact exit code, stdout, stderr, duration, and whether files changed:

- **A.** `codex --version` and `codex exec --help` (confirms enforceable `--sandbox`).
- **B.** A tiny no-repo prompt asking only for `{"ok":true,"message":"riskradar codex check"}`.
- **C.** A tiny single-file edit (`codex-check.txt`: `before` → `after`) in a disposable workspace.

## Bounded live remediation

`pnpm verify:codex-live` keeps the Codex task small and lets RiskRadar own validation:

- Codex is given a compact prompt to update one dependency in `package.json` only, no commands, no refactors, no lockfile edits.
- RiskRadar then runs `npm install --package-lock-only --ignore-scripts`, `npm ci --ignore-scripts`, `npm test`, and `npm run build`.
- The live timeout defaults to `300000ms` (overridable with `CODEX_TIMEOUT_MS`); the normal timeout stays configurable.
- If Codex times out, fails, is unavailable, or makes no change, RiskRadar marks the Codex status honestly and runs the deterministic npm fallback. Codex completion is reported only when real file changes are detected.

OpenAI SDK and Vercel AI SDK adapters are also available for remediation plans. They are plan-only because they do not have Codex CLI's local workspace-editing semantics.

Verified locally:

- Codex unavailable path.
- Codex timeout path.
- Enforced sandbox flag detection.
- Workspace secret exclusion.

Not live-tested in this verification sprint:

- A full Codex remediation run. Run only against a disposable fixture repository (`RISKRADAR_TEST_REPO`).
