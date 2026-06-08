import { NextRequest, NextResponse } from "next/server";
import {
  FAILOVER_CONSENT_OPTIONS,
  JsonDatabase,
  RiskRadarError,
  RiskRadarService,
  answerTelegramCallback,
  apiError,
  applyPatch,
  chatAllowed,
  createAuditReceipt,
  editTelegramMessageText,
  getEnv,
  now,
  parseTelegramCallback,
  validateTelegramWebhookSecret,
  verifyApprovalToken
} from "@riskradar/core";

type Action = "approve" | "reject" | (typeof FAILOVER_CONSENT_OPTIONS)[number] | "start" | "dismiss";

// Applies a remediation approve/reject decision by approval id. Returns the new status.
function applyApprovalDecision(db: JsonDatabase, approvalId: string, action: "approve" | "reject", chatId: number | string): string {
  let status = "not_found";
  db.update((state) => {
    const approval = state.approvals.find((item) => item.id === approvalId);
    if (!approval) return;
    if (approval.status !== "pending") { status = approval.status; return; }
    if (new Date(approval.expiresAt).getTime() < Date.now()) { approval.status = "expired"; approval.updatedAt = now(); status = "expired"; return; }
    approval.status = action === "approve" ? "approved" : "rejected";
    approval.updatedAt = now();
    status = approval.status;
    const job = state.remediationJobs.find((item) => item.id === approval.remediationJobId);
    if (job) job.status = approval.status === "approved" ? "approved" : "rejected";
  });
  if (status === "approved" && getEnv("RISKRADAR_APPLY_LOCAL_PATCH_ON_APPROVAL") === "true") {
    const state = db.read();
    const approval = state.approvals.find((item) => item.id === approvalId);
    const job = approval ? state.remediationJobs.find((item) => item.id === approval.remediationJobId) : undefined;
    const project = job ? state.projects.find((item) => item.id === job.projectId) : undefined;
    if (job?.patchPath && project?.localPath && !job.patchAppliedAt) {
      applyPatch(project.localPath, job.patchPath);
      db.update((draft) => {
        const stored = draft.remediationJobs.find((item) => item.id === job.id);
        if (stored) { stored.patchAppliedAt = now(); stored.rollbackStatus = "available"; }
      });
    }
  }
  createAuditReceipt(db, { actorType: "user", actorId: String(chatId), channel: "telegram", action: `approval.${status}`, targetType: "approval_request", targetId: approvalId, approvalChannel: "telegram", outputSummary: { action, status } });
  return status;
}

// Human-readable label for a finding: "lodash 4.17.11 -> 4.18.0".
function findingLabel(db: JsonDatabase, findingId: string): string {
  const finding = db.read().findings.find((item) => item.id === findingId);
  return finding ? `${finding.packageName} ${finding.currentVersion} -> ${finding.fixedVersion ?? "?"}` : "dependency";
}

// What exactly an approval covers: package, version bump, and changed files.
function approvalLabel(db: JsonDatabase, approvalId: string): string {
  const state = db.read();
  const approval = state.approvals.find((item) => item.id === approvalId);
  const job = approval ? state.remediationJobs.find((item) => item.id === approval.remediationJobId) : undefined;
  const base = job ? findingLabel(db, job.findingId) : "remediation";
  const count = job?.changedFiles?.length ?? 0;
  const files = count > 0 ? ` · ${count} file${count > 1 ? "s" : ""} (${job!.changedFiles.join(", ")})` : "";
  return `${base}${files}`;
}

// What a provider-failover consent covers: package + the provider being approved.
function consentLabel(db: JsonDatabase, consentId: string): string {
  const state = db.read();
  const consent = state.providerConsents?.find((item) => item.id === consentId);
  if (!consent) return "provider failover";
  return `${findingLabel(db, consent.findingId)} via ${consent.candidateProvider}`;
}

export async function POST(request: NextRequest) {
  try {
    validateTelegramWebhookSecret(request.headers.get("X-Telegram-Bot-Api-Secret-Token"));
    const update = await request.json() as {
      callback_query?: { id?: string; data?: string; from?: { id: number }; message?: { message_id?: number; chat?: { id: number } } };
    };
    const callback = update.callback_query;
    const chatId = callback?.message?.chat?.id ?? callback?.from?.id;
    if (!callback?.data || !chatId) return NextResponse.json({ ok: true, ignored: true });
    if (!chatAllowed(chatId)) {
      return NextResponse.json({ error: { code: "telegram_chat_unauthorized", message: "This Telegram chat is not allowed to approve RiskRadar actions.", details: {} } }, { status: 403 });
    }

    const db = new JsonDatabase();
    const service = new RiskRadarService(db);
    const messageId = callback.message?.message_id;

    // Instant feedback helper: stop the spinner (toast) and replace the message
    // text (which also clears the now-stale buttons). Both are best-effort.
    const ack = async (toast: string, edited?: string) => {
      if (callback.id) await answerTelegramCallback(callback.id, toast);
      if (edited && messageId) await editTelegramMessageText(chatId, messageId, edited);
    };
    // Run heavy remediation AFTER we've acked + returned 200. Telegram drops the
    // callback (button just spins, no toast) and retries the webhook if the HTTP
    // response is slow, so the slow work must never block the response.
    const runInBackground = (work: () => Promise<string>) => {
      void (async () => {
        try {
          const finalText = await work();
          if (messageId) await editTelegramMessageText(chatId, messageId, finalText);
        } catch (error) {
          const message = error instanceof Error ? error.message : "failed";
          if (messageId) await editTelegramMessageText(chatId, messageId, `RiskRadar: remediation error — ${message}`.slice(0, 300));
        }
      })();
    };

    let toast = "";

    // Preferred path: short inline-button payloads (kind:id:action). The Telegram
    // secret header + chat allowlist authenticate the request (no token to copy).
    const tap = parseTelegramCallback(callback.data);
    if (tap) {
      if (tap.kind === "a" && (tap.action === "approve" || tap.action === "reject")) {
        // Fast: just a DB status flip (+ optional local patch). Ack right away,
        // and say exactly WHAT was approved (package, version bump, files).
        const detail = approvalLabel(db, tap.id);
        const status = applyApprovalDecision(db, tap.id, tap.action, chatId);
        toast = (status === "approved" ? `Approved ✅ ${detail}` : status === "rejected" ? `Rejected ❌ ${detail}` : `Already ${status}`).slice(0, 200);
        const edited = status === "approved" || status === "rejected"
          ? `RiskRadar remediation ${status}:\n${detail}`
          : `RiskRadar remediation: already ${status}`;
        await ack(toast, edited);
      } else if (tap.kind === "c" && (FAILOVER_CONSENT_OPTIONS as readonly string[]).includes(tap.action)) {
        // Heavy: approving consent can trigger remediation. Ack first, work after.
        const cdetail = consentLabel(db, tap.id);
        if (tap.action === "reject") {
          await service.resolveProviderConsent(tap.id, "reject" as (typeof FAILOVER_CONSENT_OPTIONS)[number], String(chatId));
          toast = `Failover rejected ❌ ${cdetail}`.slice(0, 200);
          await ack(toast, `RiskRadar provider failover rejected:\n${cdetail}`);
        } else {
          toast = `Approved ⏳ ${cdetail}`.slice(0, 200);
          await ack(toast, `RiskRadar provider failover approved:\n${cdetail}\nRemediation running…`);
          runInBackground(async () => {
            const result = await service.resolveProviderConsent(tap.id, tap.action as (typeof FAILOVER_CONSENT_OPTIONS)[number], String(chatId));
            return `RiskRadar provider failover ${result.status} ✅\n${cdetail}`;
          });
        }
      } else if (tap.kind === "w" && tap.action === "start") {
        // Heavy: full guarded remediation (scan→fix→validate). Ack first, work after.
        const wdetail = findingLabel(db, tap.id);
        toast = `Remediation started ⏳ ${wdetail}`.slice(0, 200);
        await ack(toast, `RiskRadar watch: remediation running for ${wdetail}…`);
        runInBackground(async () => {
          const result = await service.startGuardedRemediation(tap.id);
          createAuditReceipt(db, { actorType: "user", actorId: String(chatId), channel: "telegram", action: "watch.remediation_requested", targetType: "finding", targetId: tap.id, outputSummary: { outcome: result.outcome } });
          return `RiskRadar watch: remediation ${result.outcome} ✅\n${wdetail}`;
        });
      } else if (tap.kind === "w" && tap.action === "dismiss") {
        const wdetail = findingLabel(db, tap.id);
        toast = `Dismissed 🔕 ${wdetail}`.slice(0, 200);
        await ack(toast, `RiskRadar watch: dismissed\n${wdetail}`);
        createAuditReceipt(db, { actorType: "user", actorId: String(chatId), channel: "telegram", action: "watch.dismissed", targetType: "finding", targetId: tap.id, outputSummary: {} });
      } else if (tap.kind === "g" && tap.action === "push") {
        // Push gate: heavy (clone + push + open PR). Ack first, run in background.
        toast = "Pushing branch + opening PR ⏳";
        await ack(toast, "RiskRadar: pushing the branch and opening the PR…");
        runInBackground(async () => {
          const job = await service.confirmPush(tap.id, String(chatId));
          // The merge gate is sent separately by confirmPush; this edits the push message.
          const pr = new JsonDatabase().read().pullRequests.find((item) => item.remediationJobId === job.id);
          return pr?.url ? `RiskRadar: PR opened ✅\n${pr.url}\n(merge gate sent as a separate message)` : `RiskRadar: branch pushed (${job.status}) ✅ — merge gate sent.`;
        });
      } else if (tap.kind === "g" && tap.action === "discard") {
        await service.discardPush(tap.id, String(chatId));
        toast = "Discarded 🗑";
        await ack(toast, "RiskRadar: fix discarded — nothing was pushed.");
      } else if (tap.kind === "m" && tap.action === "merge") {
        // Merge gate: heavy (GitHub merge). Ack first, run in background.
        const pr0 = db.read().pullRequests.find((item) => item.remediationJobId === tap.id);
        toast = pr0?.number ? `Merging PR #${pr0.number} ⏳` : "Merging ⏳";
        await ack(toast, `RiskRadar: merging${pr0?.number ? ` PR #${pr0.number}` : " the PR"}…`);
        runInBackground(async () => {
          await service.confirmMerge(tap.id, String(chatId));
          const pr = new JsonDatabase().read().pullRequests.find((item) => item.remediationJobId === tap.id);
          return pr?.url ? `RiskRadar: PR #${pr.number} merged ✅\n${pr.url}` : "RiskRadar: PR merged ✅";
        });
      } else if (tap.kind === "m" && tap.action === "reject") {
        const pr0 = db.read().pullRequests.find((item) => item.remediationJobId === tap.id);
        toast = pr0?.number ? `Rejecting PR #${pr0.number} ⏳` : "Rejecting ⏳";
        await ack(toast, `RiskRadar: closing${pr0?.number ? ` PR #${pr0.number}` : " the PR"} + deleting the branch…`);
        runInBackground(async () => {
          await service.rejectMerge(tap.id, String(chatId));
          return `RiskRadar: PR${pr0?.number ? ` #${pr0.number}` : ""} closed, branch deleted ❌`;
        });
      } else {
        toast = "Unknown action";
        await ack(toast);
      }
    } else {
      // Legacy path: long signed token in callback_data (back-compat).
      const payload = verifyApprovalToken(callback.data);
      const consent = db.read().providerConsents?.find((item) => item.id === payload.approvalId);
      if (consent && (FAILOVER_CONSENT_OPTIONS as readonly string[]).includes(payload.action)) {
        toast = "Processing ⏳";
        await ack(toast, "RiskRadar provider failover: processing…");
        runInBackground(async () => {
          const result = await service.resolveProviderConsent(consent.id, payload.action as (typeof FAILOVER_CONSENT_OPTIONS)[number], String(chatId));
          return `RiskRadar provider failover: ${result.status} ✅`;
        });
      } else if (payload.action === "approve" || payload.action === "reject") {
        const status = applyApprovalDecision(db, payload.approvalId, payload.action, chatId);
        toast = `Remediation ${status}`;
        await ack(toast, `RiskRadar remediation: ${status}`);
      } else {
        toast = "Unsupported token action";
        await ack(toast);
      }
    }

    return NextResponse.json({ ok: true, result: toast });
  } catch (error) {
    return NextResponse.json(apiError(error), { status: error instanceof RiskRadarError ? error.status : 400 });
  }
}
