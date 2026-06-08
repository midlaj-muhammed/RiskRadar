import { JsonDatabase, RiskRadarService, getSettings, runWatchCycle, watchStatus } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// pnpm worker:watch — continuous watch loop. Disabled unless RISKRADAR_WATCH_ENABLED=true
// (or settings enable it). Never auto-patches; only scans, records, and alerts.
const db = new JsonDatabase();
const service = new RiskRadarService(db);
const settings = getSettings(db);

if (!settings.watch.enabled) {
  console.log(safeJson({ service: "riskradar-watch", enabled: false, message: "Watch mode is disabled. Set RISKRADAR_WATCH_ENABLED=true (or enable in dashboard settings) to start.", status: watchStatus(db) }));
  process.exit(0);
}

const intervalMs = Math.max(1, settings.watch.intervalMinutes) * 60_000;
console.log(safeJson({ service: "riskradar-watch", enabled: true, intervalMinutes: settings.watch.intervalMinutes, message: "Watch loop started. Scans run on the configured interval; remediation always requires approval." }));

async function cycle() {
  try {
    const run = await runWatchCycle({ db, scanAll: () => service.scanAll() });
    console.log(safeJson({ at: new Date().toISOString(), run, status: watchStatus(db) }));
  } catch (error) {
    console.error(safeJson({ at: new Date().toISOString(), error: error instanceof Error ? error.message : String(error) }));
  }
}

await cycle();
setInterval(() => { void cycle(); }, intervalMs);
