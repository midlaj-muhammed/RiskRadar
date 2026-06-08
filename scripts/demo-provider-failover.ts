import { cpSync, existsSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { JsonDatabase, RiskRadarService, classifyAgentRemediation, clearReadinessCache, updateSettings } from "../packages/core/src/index.ts";
import { loadDotenvFile, optionalEnv, safeJson } from "./live-utils.ts";

loadDotenvFile();

// End-to-end failover demo:
// 1. Simulate Codex quota exceeded (CODEX_ENABLED=false).
// 2. Ladder detects the next ready provider; in ask mode it requests consent.
// 3. Auto-approve the consent (allow_once) to mirror a user tapping "Allow once".
// 4. The approved provider returns a strict JSON plan; RiskRadar applies it,
//    validates, and produces a draft PR / local patch. Honest about the outcome.
async function main() {
  if (!optionalEnv("RISKRADAR_AGENT_MODEL")) process.env.RISKRADAR_AGENT_MODEL = "qwen2.5-coder:7b";
  const model = optionalEnv("RISKRADAR_AGENT_MODEL");
  const root = path.join(os.tmpdir(), `riskradar-failover-demo-${Date.now()}`);
  const fixture = path.join(root, "fixture");
  cpSync(path.join(process.cwd(), "tests", "fixtures", "vulnerable-npm-project"), fixture, { recursive: true });
  process.env.RISKRADAR_DATA_FILE = path.join(root, "db.json");
  process.env.RISKRADAR_LOG_DIR = path.join(root, "logs");
  process.env.RISKRADAR_WORKSPACE_DIR = path.join(root, "workspaces");
  process.env.RISKRADAR_LOCAL_ROOTS = root;
  process.env.RISKRADAR_RETAIN_WORKSPACES = "true";
  process.env.CODEX_ENABLED = "false";
  process.env.TELEGRAM_ALLOWED_CHAT_IDS = "";
  clearReadinessCache();
  try {
    const db = new JsonDatabase(process.env.RISKRADAR_DATA_FILE);
    const service = new RiskRadarService(db);
    // Chain prefers a local model so the demo exercises the consent path.
    updateSettings(db, { failover: { mode: "ask", chain: ["codex", "openrouter", "ollama", "deterministic"], requireConsentForLowerTrust: true, allowLocalFailover: false } });
    const project = await service.createProject({ sourceType: "local", localPath: fixture, name: "riskradar-failover-demo" });
    await service.scanProject(project.id);
    const finding = db.read().findings.find((item) => item.status === "fix_available" && item.fixedVersion);
    if (!finding) throw new Error("No fixable fixture finding found.");

    const ladder = await service.startGuardedRemediation(finding.id);
    let resolved: { status: string; jobStatus?: string; agent?: string } | undefined;
    if (ladder.outcome === "consent_requested" && ladder.consent) {
      const result = await service.resolveProviderConsent(ladder.consent.id, "allow_once", "demo");
      resolved = { status: result.status, jobStatus: result.job?.status, agent: result.job?.agent };
    }
    let finalJob = db.read().remediationJobs.slice(-1)[0];
    if (finalJob && !classifyAgentRemediation(finalJob).completed && finding.fixedVersion) {
      finalJob = await service.startRemediation(finding.id, "deterministic-npm");
    }
    const completed = finalJob ? classifyAgentRemediation(finalJob).completed : false;
    const ok = Boolean(finalJob) && completed;

    console.log(safeJson({
      ok,
      agentModel: model,
      ladderOutcome: ladder.outcome,
      timeline: ladder.timeline,
      decision: ladder.decision,
      consentResolved: resolved,
      finalJob: finalJob ? { agent: finalJob.agent, status: finalJob.status, changedFiles: finalJob.changedFiles, patchPath: finalJob.patchPath, completed } : undefined,
      note: "If no local model is reachable, the ladder honestly lands on deterministic fallback — never a faked success."
    }));
    if (!ok) process.exit(1);
  } finally {
    if (process.env.RISKRADAR_RETAIN_WORKSPACES !== "true" && existsSync(root)) rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
