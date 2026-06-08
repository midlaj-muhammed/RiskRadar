import { cpSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  JsonDatabase,
  RiskRadarService,
  buildScopedCodexPrompt,
  classifyCodexRemediation,
  codexStatus,
  createAuditReceipt
} from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Step 4: live Codex remediation gets a larger default timeout (300000ms) so a
// bounded edit can finish reliably. An explicit CODEX_TIMEOUT_MS wins; the normal
// (non-live) timeout behaviour stays configurable through the same variable.
const liveTimeoutMs = process.env.CODEX_TIMEOUT_MS ? Number(process.env.CODEX_TIMEOUT_MS) : 300000;

async function main() {
  const status = codexStatus();
  const root = path.join(os.tmpdir(), `riskradar-codex-live-${Date.now()}`);
  const fixture = path.join(root, "fixture");
  cpSync(path.join(process.cwd(), "tests", "fixtures", "vulnerable-npm-project"), fixture, { recursive: true });
  // Plant secret-like files to prove the workspace copy scrubs them.
  writeFileSync(path.join(fixture, ".env"), "SECRET_SHOULD_NOT_COPY=super-secret-value");
  writeFileSync(path.join(fixture, "private.key"), "PRIVATE_KEY_SHOULD_NOT_COPY");
  process.env.RISKRADAR_DATA_FILE = path.join(root, "db.json");
  process.env.RISKRADAR_LOG_DIR = path.join(root, "logs");
  process.env.RISKRADAR_WORKSPACE_DIR = path.join(root, "workspaces");
  process.env.RISKRADAR_LOCAL_ROOTS = root;
  process.env.RISKRADAR_RETAIN_WORKSPACES = "true";
  // This verifier exercises Codex remediation + the deterministic fallback, not
  // the Telegram channel (that is verify:telegram-live). Suppress approval sends
  // so the run never depends on, or spams, the phone channel.
  const previousAllowedChats = process.env.TELEGRAM_ALLOWED_CHAT_IDS;
  process.env.TELEGRAM_ALLOWED_CHAT_IDS = "";
  try {
    const db = new JsonDatabase(process.env.RISKRADAR_DATA_FILE);
    const service = new RiskRadarService(db);
    const project = await service.createProject({ sourceType: "local", localPath: fixture, name: "riskradar-codex-live-fixture" });
    await service.scanProject(project.id);
    const finding = db.read().findings.find((item) => item.projectId === project.id && item.status === "fix_available" && item.fixedVersion);
    if (!finding) throw new Error("No fixable fixture finding found for Codex live verification.");

    // Step 3: compact, bounded prompt. Codex only edits package.json; it must not
    // run install/test/build. RiskRadar owns validation (ownLockfile: true).
    const scopedPrompt = buildScopedCodexPrompt({
      packageName: finding.packageName,
      currentVersion: finding.currentVersion,
      fixedVersion: finding.fixedVersion!
    });

    const job = status.configured
      ? await service.startRemediation(finding.id, "codex", { codexPrompt: scopedPrompt, codexTimeoutMs: liveTimeoutMs, ownLockfile: true })
      : {
          id: "codex_not_started",
          status: "codex_not_executed" as const,
          errorCode: "codex_unavailable",
          errorMessage: `Codex unavailable: ${status.message}`,
          changedFiles: [] as string[],
          workspacePath: undefined,
          patchPath: undefined
        };

    const outcome = classifyCodexRemediation(job);
    const workspace = job.workspacePath;
    const secretCopied = workspace ? existsSync(path.join(workspace, ".env")) || existsSync(path.join(workspace, "private.key")) : false;

    // Step 5: only fall back when Codex did not genuinely complete.
    let fallbackJob: Awaited<ReturnType<RiskRadarService["startRemediation"]>> | undefined;
    if (outcome.shouldFallback) {
      fallbackJob = await service.startRemediation(finding.id, "deterministic-npm");
    }
    const fallbackOk = fallbackJob ? fallbackJob.status === "pr_ready" || fallbackJob.status === "approval_sent" : false;

    createAuditReceipt(db, {
      projectId: project.id,
      actorType: "system",
      agent: "codex",
      action: "verification.codex_live",
      targetType: "remediation_job",
      targetId: job.id,
      changedFiles: job.changedFiles,
      outputSummary: {
        codexStatus: outcome.codexStatus,
        codexCompleted: outcome.codexCompleted,
        status: job.status,
        errorCode: job.errorCode,
        secretCopied,
        usedDeterministicFallback: Boolean(fallbackJob),
        fallbackStatus: fallbackJob?.status
      }
    });

    const logs = existsSync(path.join(root, "logs")) ? "captured" : "none";
    // Honest gate: pass when no secret leaked AND either Codex truly completed
    // with detected file changes, OR the deterministic fallback produced a fix.
    // Codex success is never faked: codexCompleted comes only from real changes.
    const ok = !secretCopied && (outcome.codexCompleted || (outcome.shouldFallback && fallbackOk));

    console.log(safeJson({
      ok,
      codexAvailable: status.configured,
      codexMessage: status.message,
      codexStatus: outcome.codexStatus,
      codexCompleted: outcome.codexCompleted,
      codexLiveTimeoutMs: liveTimeoutMs,
      scopedPrompt,
      status: job.status,
      errorCode: job.errorCode,
      errorMessage: job.errorMessage,
      changedFiles: job.changedFiles,
      patchPath: job.patchPath,
      workspacePath: workspace,
      secretFilesCopied: secretCopied,
      usedDeterministicFallback: Boolean(fallbackJob),
      deterministicFallback: fallbackJob ? {
        status: fallbackJob.status,
        errorCode: fallbackJob.errorCode,
        changedFiles: fallbackJob.changedFiles,
        patchPath: fallbackJob.patchPath
      } : undefined,
      logs
    }));
    if (!ok) process.exit(1);
  } finally {
    if (previousAllowedChats === undefined) delete process.env.TELEGRAM_ALLOWED_CHAT_IDS;
    else process.env.TELEGRAM_ALLOWED_CHAT_IDS = previousAllowedChats;
    if (process.env.RISKRADAR_RETAIN_WORKSPACES !== "true") rmSync(root, { recursive: true, force: true });
    else if (existsSync(path.join(root, "logs"))) {
      const marker = path.join(root, "README.txt");
      writeFileSync(marker, "RiskRadar retained this Codex verification workspace for inspection. Remove it after review.\n");
      readFileSync(marker, "utf8");
    }
  }
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
