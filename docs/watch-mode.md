# Watch Mode

Continuous monitoring that is safe by default. Watch mode periodically re-scans
inventoried projects, records new findings, updates Threat Radar, and (optionally)
alerts via Telegram, but **never patches automatically**. Every remediation
still requires explicit approval.

## Enable

```
RISKRADAR_WATCH_ENABLED=false            # default off
RISKRADAR_WATCH_INTERVAL_MINUTES=60
RISKRADAR_WATCH_TELEGRAM_ALERTS=true
RISKRADAR_QUIET_HOURS=23:00-07:00        # suppress non-critical alerts overnight
```

Or toggle from the dashboard **Watch Mode** page (writes to local settings).

```bash
pnpm worker:watch        # run the loop (prints disabled status if not enabled)
pnpm verify:watch-mode   # disabled-by-default + enabled scan + dedup + no-auto-patch
pnpm demo:watch          # narrated two-cycle demo
```

## Behaviour

- **Disabled by default**: `worker:watch` prints a disabled status and exits.
- **No auto-remediation, no auto-merge, no auto-deploy.**
- **Deduplication** by `projectId + advisoryId + package + version`: the same
  finding never re-alerts.
- **Quiet hours** suppress non-critical alerts; they re-surface in a later cycle.
- **Telegram alert** asks "New vulnerability found. Start remediation?", if
  Telegram is not configured, the finding is recorded and shown on the dashboard.
- Status (`enabled`, last/next run, last error, findings discovered, alerts sent,
  deduped) is exposed at `/api/watch`, the `/watch` page, and the MCP tool
  `riskradar.get_watch_status`.
- If provider failover is needed during a watch-triggered remediation, it follows
  the consent ladder in `docs/model-providers.md`.

## Limitations

- Single-process interval loop (no durable scheduler). It is "pull" monitoring:
  it re-queries OSV for your dependencies on a schedule, not a live push feed.
