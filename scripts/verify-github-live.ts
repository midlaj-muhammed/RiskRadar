import { JsonDatabase, RiskRadarService } from "../packages/core/src/index.ts";
import { assertGithubRepoAccessible, loadDotenvFile, parseTestRepo, safeJson } from "./live-utils.ts";

loadDotenvFile();

async function main() {
  const repo = parseTestRepo();
  await assertGithubRepoAccessible(repo);
  const db = new JsonDatabase();
  const service = new RiskRadarService(db);
  const project = await service.createProject({ sourceType: "github", githubOwner: repo.owner, githubRepo: repo.repo });
  const scan = await service.scanProject(project.id);
  const state = db.read();
  const findings = state.findings.filter((finding) => finding.projectId === project.id);
  const auditReceipts = state.auditReceipts.filter((receipt) => receipt.targetId === scan.id || receipt.projectId === project.id);
  console.log(safeJson({
    ok: scan.status === "completed",
    projectId: project.id,
    repo: `${repo.owner}/${repo.repo}`,
    scan: { id: scan.id, status: scan.status, scanner: scan.scanner },
    findings: findings.map((finding) => ({
      id: finding.id,
      packageName: finding.packageName,
      currentVersion: finding.currentVersion,
      fixedVersion: finding.fixedVersion,
      riskScore: finding.riskScore,
      riskLevel: finding.riskLevel,
      scanConfidence: finding.scanConfidence,
      status: finding.status
    })),
    auditReceipts: auditReceipts.length
  }));
  if (scan.status !== "completed") process.exit(1);
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
