import { cpSync, existsSync, readFileSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { JsonDatabase, RiskRadarService, createAuditReceipt } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// End-to-end PyPI flow: scan a Python project (requirements.txt) via OSV, find a
// fixable PyPI vulnerability, and have RiskRadar apply the requirements.txt pin
// + write a local patch. Proves multi-ecosystem scan→remediate (no GitHub/Telegram).
async function main() {
  const root = path.join(os.tmpdir(), `riskradar-python-e2e-${Date.now()}`);
  const fixture = path.join(root, "fixture");
  cpSync(path.join(process.cwd(), "tests", "fixtures", "vulnerable-python-project"), fixture, { recursive: true });
  process.env.RISKRADAR_DATA_FILE = path.join(root, "db.json");
  process.env.RISKRADAR_LOG_DIR = path.join(root, "logs");
  process.env.RISKRADAR_WORKSPACE_DIR = path.join(root, "workspaces");
  process.env.RISKRADAR_LOCAL_ROOTS = root;
  process.env.RISKRADAR_RETAIN_WORKSPACES = "true";
  process.env.TELEGRAM_ALLOWED_CHAT_IDS = "";
  try {
    const db = new JsonDatabase(process.env.RISKRADAR_DATA_FILE);
    const service = new RiskRadarService(db);
    const project = await service.createProject({ sourceType: "local", localPath: fixture, name: "riskradar-python-e2e" });
    const scan = await service.scanProject(project.id);
    const pypiFindings = db.read().findings.filter((f) => f.projectId === project.id && /pypi/i.test(f.ecosystem));
    const fixable = pypiFindings.find((f) => f.status === "fix_available" && f.fixedVersion);

    let job: Awaited<ReturnType<RiskRadarService["startRemediation"]>> | undefined;
    let patchContainsRequirements = false;
    if (fixable) {
      job = await service.startRemediation(fixable.id, "deterministic-npm");
      if (job.patchPath && existsSync(job.patchPath)) {
        patchContainsRequirements = readFileSync(job.patchPath, "utf8").includes("requirements.txt");
      }
    }
    createAuditReceipt(db, { projectId: project.id, actorType: "system", action: "verification.python_e2e", targetType: "scan_job", targetId: scan.id, outputSummary: { pypiFindings: pypiFindings.length, remediated: job?.status } });

    const ok = pypiFindings.length > 0 && Boolean(fixable) && (job?.status === "pr_ready" || job?.status === "approval_sent") && patchContainsRequirements;
    console.log(safeJson({
      ok,
      scanner: scan.scanner,
      pypiFindings: pypiFindings.length,
      sample: pypiFindings.slice(0, 4).map((f) => `${f.packageName}@${f.currentVersion} -> ${f.fixedVersion ?? "?"} [${f.ecosystem}] ${f.riskLevel}`),
      remediation: job ? { status: job.status, agent: job.agent, changedFiles: job.changedFiles, patchPath: job.patchPath } : "no fixable PyPI finding",
      patchUpdatesRequirements: patchContainsRequirements
    }));
    if (!ok) process.exit(1);
  } finally {
    if (process.env.RISKRADAR_RETAIN_WORKSPACES !== "true") rmSync(root, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
