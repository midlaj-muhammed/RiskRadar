import { JsonDatabase, RiskRadarService, getSettings, hydrateFromPostgres, integrationHealth, postgresStatus, queueEnabled, queueStatus, runWatchCycle, scheduleWatchCycle, startQueueWorker, watchStatus } from "@riskradar/core";

const db = new JsonDatabase();
const service = new RiskRadarService(db);

async function main() {
  // Hydrate the local working copy from Postgres (durable system of record) when enabled.
  const hydrated = await hydrateFromPostgres(db);

  console.log(JSON.stringify({
    service: "riskradar-worker",
    mode: queueEnabled() ? "redis-queue" : "local-inline",
    hydratedFromPostgres: hydrated,
    postgres: await postgresStatus(),
    queue: await queueStatus(),
    message: queueEnabled()
      ? "Redis durable queue mode. Processing jobs + repeatable watch schedule."
      : "Local inline mode is ready. API-triggered scans execute through the shared service.",
    integrations: integrationHealth()
  }, null, 2));

  if (process.argv.includes("--scan-all")) {
    console.log(JSON.stringify(await service.scanAll(), null, 2));
    return;
  }

  if (queueEnabled()) {
    const worker = await startQueueWorker({
      scan: (projectId) => service.scanProject(projectId),
      scanAll: () => service.scanAll(),
      remediate: (findingId) => service.startGuardedRemediation(findingId),
      watchCycle: () => runWatchCycle({ db, scanAll: () => service.scanAll() })
    });
    const settings = getSettings(db);
    if (settings.watch.enabled) {
      await scheduleWatchCycle(settings.watch.intervalMinutes);
      console.log(JSON.stringify({ watch: "scheduled (durable)", status: watchStatus(db) }));
    }
    console.log(JSON.stringify({ worker: "started", note: "Press Ctrl+C to stop." }));
    const shutdown = async () => { await worker.close(); process.exit(0); };
    process.on("SIGINT", shutdown);
    process.on("SIGTERM", shutdown);
  }
}

main().catch((error) => {
  console.error(JSON.stringify({ ok: false, error: error instanceof Error ? error.message : String(error) }, null, 2));
  process.exit(1);
});
