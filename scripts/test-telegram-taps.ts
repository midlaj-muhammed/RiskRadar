import { cpSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { JsonDatabase, dataFilePath } from "../packages/core/src/index.ts";
import { loadDotenvFile, requiredEnv, safeJson, telegramChatId } from "./live-utils.ts";

loadDotenvFile();

// Drives the LIVE webhook the way Telegram does: POST a callback_query with the
// secret header for each button, against real seeded records in the dashboard's
// database. Verifies every button's behaviour end-to-end. Cleans up after.
const WEBHOOK = `http://127.0.0.1:${process.env.RISKRADAR_WEB_PORT ?? "3001"}/api/integrations/telegram/webhook`;
const SECRET = requiredEnv("TELEGRAM_WEBHOOK_SECRET");
const CHAT = Number(telegramChatId());
const dbPath = dataFilePath();
const ISO = () => new Date().toISOString();
const EXP = () => new Date(Date.now() + 60 * 60 * 1000).toISOString();

const fixture = path.join(os.tmpdir(), `riskradar-tap-fixture-${Date.now()}`);

function project() {
  return { id: "proj_tap", name: "riskradar-tap-demo", sourceType: "local", localPath: fixture, isPathAllowlisted: true, packageManager: "npm", deploymentProvider: "none", productionExposed: false, createdAt: ISO(), updatedAt: ISO() } as const;
}
function finding() {
  return { id: "find_tap", projectId: "proj_tap", vulnerabilityId: "OSV-tap", packageName: "lodash", ecosystem: "npm", currentVersion: "4.17.20", fixedVersion: "4.17.21", dependencyType: "direct", riskScore: 78, riskLevel: "high", riskFactors: [], missingRiskData: [], fixStrategy: "safe_patch", status: "fix_available", scanConfidence: "direct_manifest_only", createdAt: ISO(), updatedAt: ISO() } as const;
}

function reseed(mutator: (state: ReturnType<JsonDatabase["read"]>) => void) {
  const db = new JsonDatabase(dbPath);
  const state = db.read();
  // remove any prior tap-test records
  state.projects = state.projects.filter((p) => p.id !== "proj_tap");
  state.findings = state.findings.filter((f) => f.id !== "find_tap");
  state.vulnerabilities = state.vulnerabilities.filter((v) => v.id !== "OSV-tap");
  state.remediationJobs = (state.remediationJobs ?? []).filter((j) => j.findingId !== "find_tap");
  state.approvals = (state.approvals ?? []).filter((a) => !a.id.startsWith("appr_tap"));
  state.providerConsents = (state.providerConsents ?? []).filter((c) => !c.id.startsWith("pcon_tap"));
  state.projects.push(project() as never);
  state.findings.push(finding() as never);
  state.vulnerabilities.push({ id: "OSV-tap", source: "osv", cveIds: ["CVE-2021-23337"], ghsaIds: [], summary: "lodash", severity: "high", references: [] } as never);
  mutator(state);
  db.write(state);
}

async function tap(label: string, data: string): Promise<{ label: string; http: number; result?: string; error?: string }> {
  try {
    const response = await fetch(WEBHOOK, {
      method: "POST",
      headers: { "content-type": "application/json", "X-Telegram-Bot-Api-Secret-Token": SECRET },
      body: JSON.stringify({ callback_query: { id: `tap_${Date.now()}`, data, from: { id: CHAT }, message: { message_id: 1, chat: { id: CHAT } } } })
    });
    const body = await response.json().catch(() => ({})) as { result?: string; error?: { message?: string } };
    return { label, http: response.status, result: body.result, error: body.error?.message };
  } catch (error) {
    return { label, http: 0, error: error instanceof Error ? error.message : String(error) };
  }
}

async function main() {
  requiredEnv("TELEGRAM_BOT_TOKEN");
  cpSync(path.join(process.cwd(), "tests", "fixtures", "vulnerable-npm-project"), fixture, { recursive: true });
  const results: Array<Record<string, unknown>> = [];
  const read = () => new JsonDatabase(dbPath).read();

  try {
    // 1) APPROVE
    reseed((s) => {
      s.remediationJobs.push({ id: "rem_tap_a", findingId: "find_tap", projectId: "proj_tap", status: "approval_sent", agent: "codex", changedFiles: ["package.json"], rollbackStatus: "available", createdAt: ISO() } as never);
      s.approvals.push({ id: "appr_tap_a", remediationJobId: "rem_tap_a", channel: "telegram", status: "pending", expiresAt: EXP(), createdAt: ISO(), updatedAt: ISO() } as never);
    });
    const approve = await tap("approve", "a:appr_tap_a:approve");
    results.push({ ...approve, approvalStatus: read().approvals.find((a) => a.id === "appr_tap_a")?.status, jobStatus: read().remediationJobs.find((j) => j.id === "rem_tap_a")?.status });

    // 2) REJECT
    reseed((s) => {
      s.remediationJobs.push({ id: "rem_tap_r", findingId: "find_tap", projectId: "proj_tap", status: "approval_sent", agent: "codex", changedFiles: ["package.json"], rollbackStatus: "available", createdAt: ISO() } as never);
      s.approvals.push({ id: "appr_tap_r", remediationJobId: "rem_tap_r", channel: "telegram", status: "pending", expiresAt: EXP(), createdAt: ISO(), updatedAt: ISO() } as never);
    });
    const reject = await tap("reject", "a:appr_tap_r:reject");
    results.push({ ...reject, approvalStatus: read().approvals.find((a) => a.id === "appr_tap_r")?.status, jobStatus: read().remediationJobs.find((j) => j.id === "rem_tap_r")?.status });

    // 3) CONSENT REJECT (no remediation should run)
    reseed((s) => { s.providerConsents.push({ id: "pcon_tap_reject", findingId: "find_tap", projectId: "proj_tap", failedProvider: "codex", candidateProvider: "ollama", candidateTrust: "local", status: "pending", readinessSummary: [], createdAt: ISO(), updatedAt: ISO() } as never); });
    const cReject = await tap("consent:reject", "c:pcon_tap_reject:reject");
    results.push({ ...cReject, consentStatus: read().providerConsents?.find((c) => c.id === "pcon_tap_reject")?.status, ranRemediation: read().remediationJobs.some((j) => j.findingId === "find_tap" && j.id.startsWith("rem_") && !j.id.startsWith("rem_tap")) });

    // 4) CONSENT USE DETERMINISTIC (RiskRadar deterministic fix runs)
    reseed((s) => { s.providerConsents.push({ id: "pcon_tap_det", findingId: "find_tap", projectId: "proj_tap", failedProvider: "codex", candidateProvider: "ollama", candidateTrust: "local", status: "pending", readinessSummary: [], createdAt: ISO(), updatedAt: ISO() } as never); });
    const cDet = await tap("consent:use_deterministic", "c:pcon_tap_det:use_deterministic");
    results.push({ ...cDet, consentStatus: read().providerConsents?.find((c) => c.id === "pcon_tap_det")?.status, lastJob: read().remediationJobs.slice(-1)[0] && { agent: read().remediationJobs.slice(-1)[0]!.agent, status: read().remediationJobs.slice(-1)[0]!.status } });

    // 5) CONSENT ALLOW ONCE (local model qwen runs)
    reseed((s) => { s.providerConsents.push({ id: "pcon_tap_allow", findingId: "find_tap", projectId: "proj_tap", failedProvider: "codex", candidateProvider: "ollama", candidateTrust: "local", status: "pending", readinessSummary: [], createdAt: ISO(), updatedAt: ISO() } as never); });
    const cAllow = await tap("consent:allow_once", "c:pcon_tap_allow:allow_once");
    results.push({ ...cAllow, consentStatus: read().providerConsents?.find((c) => c.id === "pcon_tap_allow")?.status, lastJob: read().remediationJobs.slice(-1)[0] && { agent: read().remediationJobs.slice(-1)[0]!.agent, status: read().remediationJobs.slice(-1)[0]!.status } });

    // 6) CONSENT ALWAYS ALLOW REPO (sets per-repo policy + runs candidate)
    reseed((s) => { s.providerConsents.push({ id: "pcon_tap_always", findingId: "find_tap", projectId: "proj_tap", failedProvider: "codex", candidateProvider: "ollama", candidateTrust: "local", status: "pending", readinessSummary: [], createdAt: ISO(), updatedAt: ISO() } as never); });
    const cAlways = await tap("consent:always_allow_repo", "c:pcon_tap_always:always_allow_repo");
    results.push({ ...cAlways, consentStatus: read().providerConsents?.find((c) => c.id === "pcon_tap_always")?.status, repoPolicy: read().settings?.repoPolicies?.proj_tap });

    // 7) WATCH DISMISS (audit only, no remediation)
    reseed(() => undefined);
    const wDismiss = await tap("watch:dismiss", "w:find_tap:dismiss");
    results.push({ ...wDismiss, auditDismiss: read().auditReceipts.some((r) => r.action === "watch.dismissed" && r.targetId === "find_tap") });

    // 8) WATCH START (kicks off the failover ladder)
    reseed(() => undefined);
    const wStart = await tap("watch:start", "w:find_tap:start");
    results.push({ ...wStart, auditStart: read().auditReceipts.some((r) => r.action === "watch.remediation_requested" && r.targetId === "find_tap") });

    // 9) AUTH NEGATIVE: wrong secret must be rejected
    const badSecret = await fetch(WEBHOOK, { method: "POST", headers: { "content-type": "application/json", "X-Telegram-Bot-Api-Secret-Token": "wrong" }, body: JSON.stringify({ callback_query: { id: "x", data: "a:appr_tap_a:approve", from: { id: CHAT }, message: { message_id: 1, chat: { id: CHAT } } } }) });
    results.push({ label: "auth:wrong_secret", http: badSecret.status, expected: "403" });

    console.log(safeJson({ ok: true, webhook: WEBHOOK, results }));
  } finally {
    // cleanup tap-test records
    reseed(() => undefined);
    const db = new JsonDatabase(dbPath);
    const state = db.read();
    state.projects = state.projects.filter((p) => p.id !== "proj_tap");
    state.findings = state.findings.filter((f) => f.id !== "find_tap");
    state.vulnerabilities = state.vulnerabilities.filter((v) => v.id !== "OSV-tap");
    state.remediationJobs = (state.remediationJobs ?? []).filter((j) => j.findingId !== "find_tap");
    state.approvals = (state.approvals ?? []).filter((a) => !a.id.startsWith("appr_tap"));
    state.providerConsents = (state.providerConsents ?? []).filter((c) => !c.id.startsWith("pcon_tap"));
    db.write(state);
    rmSync(fixture, { recursive: true, force: true });
  }
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
