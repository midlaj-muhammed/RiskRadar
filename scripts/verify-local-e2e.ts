import { cpSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const repoRoot = process.cwd();
const runRoot = path.join(os.tmpdir(), `riskradar-local-e2e-${Date.now()}`);
const fixtureSource = path.join(repoRoot, "tests", "fixtures", "vulnerable-npm-project");
const fixture = path.join(runRoot, "fixture");
const dataFile = path.join(runRoot, "riskradar.db.json");
const logDir = path.join(runRoot, "logs");
const workspaceDir = path.join(runRoot, "workspaces");

mkdirSync(runRoot, { recursive: true });
cpSync(fixtureSource, fixture, { recursive: true });

process.env.RISKRADAR_DATA_FILE = dataFile;
process.env.RISKRADAR_LOG_DIR = logDir;
process.env.RISKRADAR_WORKSPACE_DIR = workspaceDir;
process.env.RISKRADAR_LOCAL_ROOTS = runRoot;
process.env.RISKRADAR_RETAIN_WORKSPACES = "false";
process.env.TELEGRAM_BOT_TOKEN = "";
process.env.TELEGRAM_CHAT_ID = "";
process.env.TELEGRAM_ALLOWED_CHAT_IDS = "";

async function main() {
  const { JsonDatabase, RiskRadarService } = await import("../packages/core/src/index.ts");

  const db = new JsonDatabase(dataFile);
  const service = new RiskRadarService(db);
  const project = await service.createProject({ sourceType: "local", localPath: fixture, name: "riskradar-local-e2e-fixture" });
  const scan = await service.scanProject(project.id);
  const scannedState = db.read();
  const finding = scannedState.findings.find((item) => item.projectId === project.id && item.status === "fix_available" && item.fixedVersion);
  if (!finding) throw new Error("local e2e failed: no fixable OSV finding was persisted");
  if (typeof finding.riskScore !== "number") throw new Error("local e2e failed: finding has no risk score");

  const job = await service.startRemediation(finding.id, "deterministic-npm");
  if (job.status !== "pr_ready") throw new Error(`local e2e failed: remediation status ${job.status}: ${job.errorCode ?? ""} ${job.errorMessage ?? ""}`);
  if (!job.patchPath) throw new Error("local e2e failed: remediation did not write a patch artifact");
  const patch = readFileSync(job.patchPath, "utf8");
  if (!patch.includes("package.json") || !patch.includes("package-lock.json")) {
    throw new Error("local e2e failed: patch artifact does not include package.json and package-lock.json");
  }
  if (job.rollbackStatus !== "not_available") {
    throw new Error(`local e2e failed: unapplied local patch rollback should be not_available, got ${job.rollbackStatus}`);
  }

  const finalState = db.read();
  const validations = finalState.validationRuns.filter((run) => run.remediationJobId === job.id);
  if (validations.length === 0 || validations.some((run) => run.status !== "passed" && run.status !== "skipped_no_script")) {
    throw new Error("local e2e failed: validation did not pass");
  }
  const auditReceipts = finalState.auditReceipts.filter((receipt) => receipt.targetId === scan.id || receipt.targetId === job.id);
  if (auditReceipts.length === 0) throw new Error("local e2e failed: no audit receipts were written");

  const report = `# Local E2E Verification

Generated: ${new Date().toISOString()}

## Flow

local fixture project -> scan -> OSV finding -> risk score -> deterministic remediation -> validation -> patch artifact -> audit receipt -> rollback state

## Result

- Project: ${project.id} (${project.name})
- Scan: ${scan.id}, status ${scan.status}, scanner ${scan.scanner}
- Finding: ${finding.id}, ${finding.packageName} ${finding.currentVersion} -> ${finding.fixedVersion}
- Risk: ${finding.riskScore}/100 ${finding.riskLevel}
- Scan confidence: ${finding.scanConfidence}
- Remediation: ${job.id}, status ${job.status}, confidence ${job.fixConfidence}
- Changed files: ${job.changedFiles.join(", ")}
- Patch artifact: ${job.patchPath}
- Saved patch copy: docs/verification/local-e2e.patch
- Patch includes package.json: ${patch.includes("package.json")}
- Patch includes package-lock.json: ${patch.includes("package-lock.json")}
- Validation: ${validations.map((run) => `${run.command}=${run.status}`).join(", ")}
- Audit receipts for scan/remediation: ${auditReceipts.length}
- Rollback state: ${job.rollbackStatus} because the local patch artifact has not been applied.

## Workspace Handling

- Disposable root: ${runRoot}
- Remediation workspace cleanup expected: true
- Workspace directory exists only for retained/debug runs: ${workspaceDir}

## Notes

This verification uses the real OSV path configured for RiskRadar. It does not create a GitHub PR, send Telegram, or run Codex.
`;

const docsDir = path.join(repoRoot, "docs", "verification");
mkdirSync(docsDir, { recursive: true });
writeFileSync(path.join(docsDir, "local-e2e.patch"), patch);
writeFileSync(path.join(docsDir, "local-e2e.md"), report);

console.log(JSON.stringify({
  ok: true,
  projectId: project.id,
  scanId: scan.id,
  findingId: finding.id,
  remediationJobId: job.id,
  patchPath: job.patchPath,
  rollbackStatus: job.rollbackStatus,
  auditReceipts: auditReceipts.length,
  reportPath: path.join("docs", "verification", "local-e2e.md")
}, null, 2));

rmSync(runRoot, { recursive: true, force: true });
}

main().catch((error) => {
  rmSync(runRoot, { recursive: true, force: true });
  console.error(error);
  process.exit(1);
});
