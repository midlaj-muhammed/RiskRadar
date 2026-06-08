# MCP Server

Run:

```bash
pnpm mcp:dev
```

Verify the Codex plugin wiring:

```bash
pnpm verify:plugin-mcp
```

The verifier reads the local Codex plugin config from
`~/plugins/riskradar/.mcp.json`, starts the configured MCP server, lists tools,
and calls `riskradar.get_scanner_coverage`. It prints only counts/status bytes,
not secrets.

Tools exposed:

- `riskradar.list_projects`
- `riskradar.scan_project`
- `riskradar.scan_all`
- `riskradar.get_threat_radar`
- `riskradar.get_blast_radius`
- `riskradar.get_vulnerability`
- `riskradar.create_patch_job`
- `riskradar.get_job_status`
- `riskradar.run_validation`
- `riskradar.create_pr`
- `riskradar.send_approval_request`
- `riskradar.record_audit_receipt`
- `riskradar.get_audit_receipts`
- `riskradar.rollback`

Watch Commander command-center tools (real data, env names only, never secrets):

- `riskradar.get_provider_readiness`: BYO provider readiness + required env names.
- `riskradar.get_provider_failover_timeline`: recent failover/consent/attempt events.
- `riskradar.get_scanner_coverage`: scanner matrix + external tool detection.
- `riskradar.get_watch_status`: watch mode status (enabled, last/next run, counts).
- `riskradar.get_approval_queue`: pending remediation approvals + provider consents + watch alerts.
- `riskradar.start_scan`: scan a project by id.
- `riskradar.request_remediation`: run the failover ladder for a finding (respects consent gates).
- `riskradar.request_provider_failover`: explicitly trigger the failover ladder for a finding.

Tools call application services or return explicit configuration/tooling messages. They do not return fake scan, PR, approval, validation, or rollback success. `request_remediation`/`request_provider_failover` never silently switch to a lower-trust provider, in `ask` mode they create a Telegram consent request instead.

`riskradar.create_patch_job` currently creates a manual plan job through the same remediation service. Use the web/API remediation endpoint with `agent: "codex"` when you want the Codex CLI to edit a disposable workspace.
