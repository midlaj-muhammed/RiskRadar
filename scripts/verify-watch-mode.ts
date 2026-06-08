import { cpSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { JsonDatabase, RiskRadarService, runWatchCycle, updateSettings, watchStatus } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Verifies watch mode end-to-end against a disposable local fixture project:
// disabled-by-default, then enabled scan + dedup + no auto-patch.
async function main() {
  const root = path.join(os.tmpdir(), `riskradar-watch-verify-${Date.now()}`);
  const fixture = path.join(root, "fixture");
  cpSync(path.join(process.cwd(), "tests", "fixtures", "vulnerable-npm-project"), fixture, { recursive: true });
  process.env.RISKRADAR_DATA_FILE = path.join(root, "db.json");
  process.env.RISKRADAR_LOG_DIR = path.join(root, "logs");
  process.env.RISKRADAR_WORKSPACE_DIR = path.join(root, "workspaces");
  process.env.RISKRADAR_LOCAL_ROOTS = root;
  process.env.TELEGRAM_ALLOWED_CHAT_IDS = ""; // dashboard-only alerts for the verifier
  try {
    const db = new JsonDatabase(process.env.RISKRADAR_DATA_FILE);
    const service = new RiskRadarService(db);
    await service.createProject({ sourceType: "local", localPath: fixture, name: "riskradar-watch-fixture" });

    const disabledRun = await runWatchCycle({ db, scanAll: () => service.scanAll() });

    updateSettings(db, { watch: { enabled: true, intervalMinutes: 60, telegramAlerts: false } });
    const firstRun = await runWatchCycle({ db, scanAll: () => service.scanAll() });
    const secondRun = await runWatchCycle({ db, scanAll: () => service.scanAll() });
    const status = watchStatus(db);

    const ok = disabledRun.status === "skipped_quiet_hours"
      && firstRun.status === "completed"
      && secondRun.dedupedFindings >= secondRun.newFindings // repeats deduped
      && db.read().remediationJobs.length === 0;            // never auto-patches

    console.log(safeJson({
      ok,
      disabledRun: { status: disabledRun.status },
      firstRun: { status: firstRun.status, newFindings: firstRun.newFindings, alertsSent: firstRun.alertsSent },
      secondRun: { newFindings: secondRun.newFindings, alertsSent: secondRun.alertsSent, dedupedFindings: secondRun.dedupedFindings },
      autoPatched: db.read().remediationJobs.length > 0,
      status
    }));
    if (!ok) process.exit(1);
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
