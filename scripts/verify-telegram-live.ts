import { JsonDatabase, RiskRadarError, createAuditReceipt, id, now, sendTelegramApproval, signApprovalPayload, verifyApprovalToken } from "../packages/core/src/index.ts";
import { approvalSecret, loadDotenvFile, safeJson, telegramChatId } from "./live-utils.ts";

loadDotenvFile();

const minimal = process.argv.includes("--minimal");

async function main() {
  const db = new JsonDatabase();
  const chatId = telegramChatId();
  if (minimal) {
    const result = await recordTelegramAttempt(db, "verification.telegram_live_minimal_sent", "live_telegram_minimal", () => sendTelegramApproval({
      chatId,
      text: "RiskRadar Telegram live test"
    }));
    console.log(safeJson({ ok: true, mode: "minimal", messageId: result.messageId, auditReceiptId: result.receiptId }));
    return;
  }

  await recordTelegramAttempt(db, "verification.telegram_live_minimal_preflight_sent", "live_telegram_minimal_preflight", () => sendTelegramApproval({
    chatId,
    text: "RiskRadar Telegram live test"
  }));

  const state = db.read();
  const latestJob = [...state.remediationJobs].reverse().find((job) => job.status === "approval_sent" || job.status === "pr_ready");
  const latestFinding = latestJob ? state.findings.find((finding) => finding.id === latestJob.findingId) : undefined;
  const latestPr = latestJob ? state.pullRequests.find((pr) => pr.remediationJobId === latestJob.id) : undefined;
  const approvalId = id("appr_live");
  const exp = Math.floor(Date.now() / 1000) + 10 * 60;
  const token = signApprovalPayload({ approvalId, action: "approve", exp }, approvalSecret());
  const verified = verifyApprovalToken(token, approvalSecret());
  const text = [
    "RiskRadar live verification approval request",
    `Project: ${latestJob?.projectId ?? "live-readiness"}`,
    `Package: ${latestFinding?.packageName ?? "n/a"}`,
    `Risk: ${latestFinding ? `${latestFinding.riskScore}/100 ${latestFinding.riskLevel}` : "n/a"}`,
    latestPr?.url ? `PR: ${latestPr.url}` : "PR: none",
    "Action: verify approval token only; no merge or deploy",
    `Signed approval token: ${token}`
  ].join("\n");
  const result = await recordTelegramAttempt(db, "verification.telegram_live_sent", approvalId, () => sendTelegramApproval({ chatId, text }));
  db.update((draft) => {
    draft.approvals.push({
      id: approvalId,
      remediationJobId: latestJob?.id ?? "live_telegram_verification",
      channel: "telegram",
      messageId: result.messageId,
      status: "pending",
      expiresAt: new Date(exp * 1000).toISOString(),
      createdAt: now(),
      updatedAt: now()
    });
  });
  console.log(safeJson({
    ok: true,
    messageId: result.messageId,
    auditReceiptId: result.receiptId,
    approvalId,
    tokenVerified: verified.approvalId === approvalId,
    webhookPublicTested: false,
    manualWebhookNote: "Use Telegram setWebhook with TELEGRAM_WEBHOOK_SECRET and post a callback query to the local route through a public tunnel if needed."
  }));
}

async function recordTelegramAttempt(
  db: JsonDatabase,
  action: string,
  targetId: string,
  send: () => Promise<{ messageId: string }>
): Promise<{ messageId: string; receiptId: string }> {
  try {
    const result = await send();
    const receipt = createAuditReceipt(db, {
      actorType: "system",
      channel: "telegram",
      action,
      targetType: "approval_request",
      targetId,
      approvalChannel: "telegram",
      outputSummary: { messageId: result.messageId }
    });
    return { ...result, receiptId: receipt.id };
  } catch (error) {
    const details = error instanceof RiskRadarError ? error.details : {};
    const receipt = createAuditReceipt(db, {
      actorType: "system",
      channel: "telegram",
      action: action.replace(/_sent$/, "_failed"),
      targetType: "approval_request",
      targetId,
      approvalChannel: "telegram",
      outputSummary: {
        code: error instanceof RiskRadarError ? error.code : "telegram_send_failed",
        message: error instanceof Error ? error.message : String(error),
        details
      }
    });
    if (error instanceof RiskRadarError) error.details = { ...error.details, auditReceiptId: receipt.id };
    throw error;
  }
}

main().catch((error) => {
  console.error(safeJson({
    ok: false,
    mode: minimal ? "minimal" : "full",
    error: error instanceof Error ? error.message : String(error),
    details: error instanceof RiskRadarError ? error.details : undefined
  }));
  process.exit(1);
});
