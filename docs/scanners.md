# Scanner Orchestration

RiskRadar orchestrates real scanners. It never fakes results: a category is
green only when a real check can run. Missing external tools show
`tool_missing` with an install hint; categories with no matching files show
`not_applicable`.

| Category | Scanner(s) | Built-in? | Notes |
|---|---|---|---|
| Dependency / SCA | OSV API + OSV-Scanner CLI | API yes / CLI optional | Lockfile + transitive when OSV-Scanner installed; otherwise direct-manifest only (confidence reported honestly). |
| Secrets | Gitleaks → built-in lightweight | fallback only | Gitleaks is authoritative. Built-in regex detector is low-confidence and clearly labeled. Raw secrets are never stored, only masked previews. |
| SAST | Semgrep | no | `tool_missing` until installed. |
| Container / IaC / license / Trivy-secrets | Trivy (`fs`) | no | `tool_missing` until installed. Does not pull/build images or scan the Docker daemon by default. |
| GitHub Actions / CI | built-in static rules | yes | write-all, pull_request_target, curl\|bash, unpinned actions, workflow_dispatch. |
| Agent / MCP config | built-in | yes | Codex sandbox/approval bypass, MCP shell/powershell/curl tools, secret-like files. |
| Malicious / suspicious package | built-in heuristics + OpenSSF data | yes | Labelled "malicious" only when matched against a configured OpenSSF data dir; otherwise "suspicious". |
| SBOM | Syft → Trivy | no | `tool_missing` until installed. Before/after diff is wired via the lockfile diff. |

Statuses: `enabled · disabled · tool_missing · not_configured · not_applicable · running · completed · error`.

## Running

```bash
pnpm verify:scanner-tools     # detect external tools (no scan) + honest coverage
pnpm verify:scanners          # run built-in scanners against a synthetic risky repo
pnpm scan:project-full [path] # run all applicable scanners (default: bundled fixture)
pnpm demo:scanner-coverage    # print the coverage matrix
```

Coverage and findings are also exposed at `/api/scanners`, the `/scanners`
dashboard page, and the MCP tool `riskradar.get_scanner_coverage`.

## Security

- Secret findings store only masked previews; raw values never leave the scanner.
- Secret findings are never sent to cloud LLM providers.
- Every external tool runs with `RISKRADAR_SCANNER_TIMEOUT_MS`.
- Scanner output is redacted before storage/logging.

Install the external tools (Gitleaks, Trivy, OSV-Scanner, Syft) with `pnpm install:scanners`. Missing tools surface as `tool_missing` in the dashboard.
