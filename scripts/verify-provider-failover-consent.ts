import { cpSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { JsonDatabase, RiskRadarService, clearReadinessCache, updateSettings } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Simulates the primary provider (Codex) being unavailable and verifies the
// failover ladder asks for consent before a lower-trust provider instead of
// silently switching. Telegram send is suppressed (dashboard-only) for the run.
async function main() {
  const root = path.join(os.tmpdir(), `riskradar-failover-consent-${Date.now()}`);
  const fixture = path.join(root, "fixture");
  cpSync(path.join(process.cwd(), "tests", "fixtures", "vulnerable-npm-project"), fixture, { recursive: true });
  process.env.RISKRADAR_DATA_FILE = path.join(root, "db.json");
  process.env.RISKRADAR_LOG_DIR = path.join(root, "logs");
  process.env.RISKRADAR_WORKSPACE_DIR = path.join(root, "workspaces");
  process.env.RISKRADAR_LOCAL_ROOTS = root;
  process.env.CODEX_ENABLED = "false";            // simulate primary provider unavailable
  process.env.TELEGRAM_ALLOWED_CHAT_IDS = "";     // dashboard-only consent
  clearReadinessCache();
  try {
    const db = new JsonDatabase(process.env.RISKRADAR_DATA_FILE);
    const service = new RiskRadarService(db);
    updateSettings(db, { failover: { mode: "ask", requireConsentForLowerTrust: true, allowLocalFailover: false } });
    const project = await service.createProject({ sourceType: "local", localPath: fixture, name: "riskradar-failover-fixture" });
    await service.scanProject(project.id);
    const finding = db.read().findings.find((item) => item.status === "fix_available" && item.fixedVersion);
    if (!finding) throw new Error("No fixable fixture finding found.");

    const result = await service.startGuardedRemediation(finding.id);
    const consent = db.read().providerConsents?.[0];
    // Honest pass: either consent was requested (ask mode, lower-trust next) and the
    // local model did NOT run, or the chain landed on a deterministic/cloud path.
    const localRanBeforeConsent = db.read().remediationJobs.some((job) => job.agent === "ollama");
    const ok = result.outcome === "consent_requested" ? !localRanBeforeConsent : ["completed", "deterministic"].includes(result.outcome);

    console.log(safeJson({
      ok,
      outcome: result.outcome,
      decision: result.decision,
      timeline: result.timeline,
      consent: consent ? { status: consent.status, candidateProvider: consent.candidateProvider, candidateTrust: consent.candidateTrust } : undefined,
      localModelRanBeforeConsent: localRanBeforeConsent
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
