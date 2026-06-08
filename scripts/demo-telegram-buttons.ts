import { cpSync, mkdirSync } from "node:fs";
import path from "node:path";
import {
  JsonDatabase,
  dataFilePath,
  logDir,
  type ProviderReadiness,
  buildFailoverConsentMessage,
  inlineKeyboard,
  sendTelegramApproval,
  telegramCallbackData
} from "../packages/core/src/index.ts";
import { loadDotenvFile, requiredEnv, safeJson, telegramChatId } from "./live-utils.ts";

loadDotenvFile();

// Seeds real PENDING records into the dashboard DB, then sends one tappable
// message per scenario. With the webhook wired (cloudflared + setWebhook), tapping
// on your phone resolves through the tunnel and the message edits to show the
// result. Heavy buttons (allow once / always / watch start) run real remediation.
const ISO = () => new Date().toISOString();
const EXP = () => new Date(Date.now() + 60 * 60 * 1000).toISOString();

async function main() {
  requiredEnv("TELEGRAM_BOT_TOKEN");
  const chatId = telegramChatId();
  // Send ONE scenario at a time for a clean, sequential chat (no burst of messages).
  // Usage: pnpm demo:telegram-buttons [approval|consent|watch|all]   (default: all)
  const scenario = (process.argv[2] ?? "all").toLowerCase();
  const want = (name: string) => scenario === "all" || scenario === name;

  // Persist a fixture so heavy taps (which copy the project) keep working later.
  const fixture = path.join(path.dirname(logDir()), "tap-demo-fixture");
  mkdirSync(path.dirname(fixture), { recursive: true });
  cpSync(path.join(process.cwd(), "tests", "fixtures", "vulnerable-npm-project"), fixture, { recursive: true });

  const approvalId = "appr_demo000001";
  const consentId = "pcon_demo000001";
  const findingId = "find_demo000001";

  const db = new JsonDatabase(dataFilePath());
  const state = db.read();
  // refresh demo records (idempotent)
  state.projects = state.projects.filter((p) => p.id !== "proj_demo");
  state.findings = state.findings.filter((f) => f.id !== findingId);
  state.vulnerabilities = state.vulnerabilities.filter((v) => v.id !== "OSV-demo");
  state.remediationJobs = (state.remediationJobs ?? []).filter((j) => j.id !== "rem_demo");
  state.approvals = (state.approvals ?? []).filter((a) => a.id !== approvalId);
  state.providerConsents = (state.providerConsents ?? []).filter((c) => c.id !== consentId);
  state.projects.push({ id: "proj_demo", name: "riskradar-tap-demo", sourceType: "local", localPath: fixture, isPathAllowlisted: true, packageManager: "npm", deploymentProvider: "none", productionExposed: false, createdAt: ISO(), updatedAt: ISO() } as never);
  state.vulnerabilities.push({ id: "OSV-demo", source: "osv", cveIds: ["CVE-2021-23337"], ghsaIds: [], summary: "lodash", severity: "high", references: [] } as never);
  state.findings.push({ id: findingId, projectId: "proj_demo", vulnerabilityId: "OSV-demo", packageName: "lodash", ecosystem: "npm", currentVersion: "4.17.20", fixedVersion: "4.17.21", dependencyType: "direct", riskScore: 78, riskLevel: "high", riskFactors: [], missingRiskData: [], fixStrategy: "safe_patch", status: "fix_available", scanConfidence: "direct_manifest_only", createdAt: ISO(), updatedAt: ISO() } as never);
  state.remediationJobs.push({ id: "rem_demo", findingId, projectId: "proj_demo", status: "approval_sent", agent: "codex", changedFiles: ["package.json"], rollbackStatus: "available", createdAt: ISO() } as never);
  state.approvals.push({ id: approvalId, remediationJobId: "rem_demo", channel: "telegram", status: "pending", expiresAt: EXP(), createdAt: ISO(), updatedAt: ISO() } as never);
  state.providerConsents.push({ id: consentId, findingId, projectId: "proj_demo", failedProvider: "codex", candidateProvider: "ollama", candidateTrust: "local", status: "pending", readinessSummary: [], createdAt: ISO(), updatedAt: ISO() } as never);
  db.write(state);

  const sent: Array<{ scenario: string; messageId: string }> = [];

  // 1) Remediation approval
  if (want("approval")) {
    const text = ["RiskRadar approval needed", "", "Project: riskradar-tap-demo", "Package: lodash", "Risk: 78/100 high", "Fix: 4.17.20 -> 4.17.21", "", "Tap a button. Nothing is merged or deployed automatically."].join("\n");
    const result = await sendTelegramApproval({ chatId, text, replyMarkup: inlineKeyboard([[
      { text: "✅ Approve", callbackData: telegramCallbackData("a", approvalId, "approve") },
      { text: "❌ Reject", callbackData: telegramCallbackData("a", approvalId, "reject") }
    ]]) });
    sent.push({ scenario: "remediation_approval", messageId: result.messageId });
  }

  // 2) Provider failover consent
  if (want("consent")) {
    const readiness: ProviderReadiness[] = [
      { provider: "codex", status: "quota_limited", trust: "codex", lastCheckedAt: ISO(), failureReason: "usage limit" },
      { provider: "openrouter", status: "not_configured", trust: "cloud", lastCheckedAt: ISO() },
      { provider: "grok", status: "endpoint_unreachable", trust: "cloud", lastCheckedAt: ISO() },
      { provider: "ollama", model: "qwen2.5-coder:7b", status: "ready", trust: "local", lastCheckedAt: ISO(), latencyMs: 421 },
      { provider: "deterministic", status: "ready", trust: "deterministic", lastCheckedAt: ISO() }
    ];
    const text = buildFailoverConsentMessage(readiness, readiness.find((r) => r.provider === "ollama")!);
    const result = await sendTelegramApproval({ chatId, text, replyMarkup: inlineKeyboard([
      [{ text: "✅ Allow once", callbackData: telegramCallbackData("c", consentId, "allow_once") }],
      [{ text: "🔓 Always allow this repo", callbackData: telegramCallbackData("c", consentId, "always_allow_repo") }],
      [{ text: "🛠 Use deterministic fix", callbackData: telegramCallbackData("c", consentId, "use_deterministic") }],
      [{ text: "❌ Reject", callbackData: telegramCallbackData("c", consentId, "reject") }]
    ]) });
    sent.push({ scenario: "provider_failover_consent", messageId: result.messageId });
  }

  // 3) Watch alert
  if (want("watch")) {
    const text = ["RiskRadar watch alert", "", "Project: riskradar-tap-demo", "Package: lodash@4.17.20", "Risk: 78/100 high", "Fix: update to 4.17.21", "", "New vulnerability found. Start remediation? (watch mode never patches automatically)"].join("\n");
    const result = await sendTelegramApproval({ chatId, text, replyMarkup: inlineKeyboard([[
      { text: "🚀 Start remediation", callbackData: telegramCallbackData("w", findingId, "start") },
      { text: "🔕 Dismiss", callbackData: telegramCallbackData("w", findingId, "dismiss") }
    ]]) });
    sent.push({ scenario: "watch_alert", messageId: result.messageId });
  }

  console.log(safeJson({
    ok: true,
    chat: "***redacted***",
    sent,
    note: "Records seeded into the dashboard DB. With the webhook wired, tapping these on your phone resolves live and the message edits to show the result. Heavy buttons run real remediation (qwen/npm) and may take ~30-60s before the message updates."
  }));
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
