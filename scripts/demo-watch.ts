import { cpSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { JsonDatabase, RiskRadarService, runWatchCycle, updateSettings, watchStatus } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Narrated watch-mode demo against a disposable fixture: enable watch, run two
// cycles, show new findings on the first and deduplication on the second, and
// confirm no auto-remediation happened.
async function main() {
  const root = path.join(os.tmpdir(), `riskradar-watch-demo-${Date.now()}`);
  const fixture = path.join(root, "fixture");
  cpSync(path.join(process.cwd(), "tests", "fixtures", "vulnerable-npm-project"), fixture, { recursive: true });
  process.env.RISKRADAR_DATA_FILE = path.join(root, "db.json");
  process.env.RISKRADAR_LOG_DIR = path.join(root, "logs");
  process.env.RISKRADAR_WORKSPACE_DIR = path.join(root, "workspaces");
  process.env.RISKRADAR_LOCAL_ROOTS = root;
  process.env.TELEGRAM_ALLOWED_CHAT_IDS = "";
  try {
    const db = new JsonDatabase(process.env.RISKRADAR_DATA_FILE);
    const service = new RiskRadarService(db);
    await service.createProject({ sourceType: "local", localPath: fixture, name: "riskradar-watch-demo" });
    updateSettings(db, { watch: { enabled: true, intervalMinutes: 60, telegramAlerts: false } });
    const cycle1 = await runWatchCycle({ db, scanAll: () => service.scanAll() });
    const cycle2 = await runWatchCycle({ db, scanAll: () => service.scanAll() });
    console.log(safeJson({
      ok: cycle1.status === "completed",
      cycle1: { newFindings: cycle1.newFindings, alertsSent: cycle1.alertsSent },
      cycle2: { newFindings: cycle2.newFindings, dedupedFindings: cycle2.dedupedFindings },
      autoRemediated: db.read().remediationJobs.length > 0,
      status: watchStatus(db),
      note: "Watch mode records findings and alerts only — remediation always requires explicit approval."
    }));
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
