import { JsonDatabase, RiskRadarError, RiskRadarService, createAuditReceipt } from "../packages/core/src/index.ts";
import { assertGithubWritePermissions, loadDotenvFile, parseTestRepo, safeJson } from "./live-utils.ts";

loadDotenvFile();

async function main() {
  const repo = parseTestRepo();
  await assertGithubWritePermissions(repo);
  const db = new JsonDatabase();
  const service = new RiskRadarService(db);
  let state = db.read();
  const project = [...state.projects].reverse().find((item) => item.sourceType === "github" && item.githubOwner === repo.owner && item.githubRepo === repo.repo);
  if (!project) throw new Error("No live GitHub project found. Run pnpm verify:github-live first.");
  const wantPkg = process.env.RISKRADAR_VERIFY_PACKAGE;
  const candidates = state.findings.filter((item) => item.projectId === project.id && item.status === "fix_available" && item.fixedVersion && (!wantPkg || item.packageName === wantPkg));
  // When a package is named, pick its biggest (breaking) fixed version so the
  // remediation exercises a real source migration, not just a patch bump.
  const major = (v?: string) => parseInt((v ?? "0").replace(/^[^0-9]*/, ""), 10) || 0;
  const finding = wantPkg
    ? [...candidates].sort((a, b) => major(b.fixedVersion) - major(a.fixedVersion))[0]
    : [...candidates].reverse()[0];
  if (!finding) throw new Error(wantPkg ? `No fixable finding for package '${wantPkg}'.` : "No fixable finding found for the live GitHub project.");
  const agent = (process.env.RISKRADAR_VERIFY_AGENT as "deterministic-npm" | "ollama" | "codex" | undefined) ?? "deterministic-npm";
  // Step 1: produce + validate the fix. The two-step flow stops at `push_pending`
  // and sends the Telegram PUSH gate.
  const job = await service.startRemediation(finding.id, agent);
  if (job.status !== "push_pending") {
    throw new RiskRadarError("github_push_gate_not_reached", "Remediation did not reach the push gate.", { status: job.status, errorCode: job.errorCode, errorMessage: job.errorMessage });
  }
  // Gate-only mode: stop here so a human taps the Push gate on Telegram (which
  // drives confirmPush -> PR -> merge gate via the live webhook).
  if (process.env.RISKRADAR_VERIFY_GATE_ONLY === "true") {
    console.log(safeJson({ ok: true, mode: "gate_only", repo: `${repo.owner}/${repo.repo}`, remediationJobId: job.id, agent, status: job.status, changedFiles: job.changedFiles, note: "Push gate sent to Telegram. Tap Push -> then Merge on your phone." }));
    return;
  }
  // Step 2: approve the PUSH gate -> branch + PR created.
  const pushed = await service.confirmPush(job.id, "verify:github-pr-live");
  state = db.read();
  const pr = state.pullRequests.find((item) => item.remediationJobId === job.id);
  // Step 3 (optional): approve the MERGE gate -> PR merged. Off by default so the
  // PR stays open for the live Telegram merge demo. Set RISKRADAR_VERIFY_MERGE=true.
  // Or exercise the REVERT path with RISKRADAR_VERIFY_REJECT=true (close PR + delete branch).
  let merged = false;
  let reverted = false;
  if (process.env.RISKRADAR_VERIFY_REJECT === "true" && pushed.status === "pr_open") {
    const rejected = await service.rejectMerge(job.id, "verify:github-pr-live");
    reverted = rejected.status === "rejected";
  } else if (process.env.RISKRADAR_VERIFY_MERGE === "true" && pushed.status === "pr_open") {
    const mergedJob = await service.confirmMerge(job.id, "verify:github-pr-live");
    merged = mergedJob.status === "merged";
  }
  createAuditReceipt(db, {
    projectId: project.id,
    actorType: "system",
    action: "verification.github_pr_live",
    targetType: "remediation_job",
    targetId: job.id,
    prLink: pr?.url,
    changedFiles: job.changedFiles,
    outputSummary: { agent, fixStatus: job.status, pushGate: pushed.status, prCreated: Boolean(pr?.url), merged, reverted }
  });
  if (!pr?.url) {
    throw new RiskRadarError("github_pr_live_failed", "Live GitHub PR verification did not create a PR.", { status: pushed.status, errorCode: pushed.errorCode, errorMessage: pushed.errorMessage });
  }
  console.log(safeJson({
    ok: true,
    repo: `${repo.owner}/${repo.repo}`,
    remediationJobId: job.id,
    agent,
    flow: { fix: "push_pending", afterPushGate: pushed.status, merged, reverted },
    changedFiles: job.changedFiles,
    pr: { url: pr.url, number: pr.number, branchName: pr.branchName, draft: pr.draft },
    cleanup: [
      `Close PR: ${pr.url}`,
      `Delete branch: ${pr.branchName}`
    ]
  }));
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
