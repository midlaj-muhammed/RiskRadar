import { JsonDatabase, id, now } from "./database";
import { getEnv } from "./env";
import { getSettings, isWithinQuietHours } from "./settings";
import { createAuditReceipt } from "./audit";
import { inlineKeyboard, sendTelegramApproval, telegramCallbackData } from "./telegram";
import type { Finding, WatchAlert, WatchRun } from "./types";

/**
 * Continuous watch mode.
 *
 * Safe by default: disabled unless explicitly enabled, never auto-patches, never
 * auto-merges/deploys. It re-scans inventoried projects, records new findings,
 * and (optionally) sends a Telegram alert asking whether to start remediation —
 * deduplicated per project+advisory+package+version so the same finding does not
 * spam alerts. Quiet hours suppress non-critical alerts.
 */
export function watchDedupeKey(projectId: string, advisoryId: string, packageName: string, version: string): string {
  return `${projectId}::${advisoryId}::${packageName}::${version}`;
}

export interface WatchStatus {
  enabled: boolean;
  intervalMinutes: number;
  quietHours?: string;
  withinQuietHours: boolean;
  telegramAlerts: boolean;
  lastRunAt?: string;
  nextRunAt?: string;
  lastError?: string;
  findingsDiscovered: number;
  alertsSent: number;
  dedupedFindings: number;
  totalCycles: number;
}

export function watchStatus(db = new JsonDatabase(), at = new Date()): WatchStatus {
  const settings = getSettings(db);
  const state = db.read();
  const runs = state.watchRuns ?? [];
  const last = runs[runs.length - 1];
  const lastRunAt = last?.finishedAt ?? last?.startedAt;
  const nextRunAt = settings.watch.enabled && lastRunAt
    ? new Date(new Date(lastRunAt).getTime() + settings.watch.intervalMinutes * 60_000).toISOString()
    : undefined;
  return {
    enabled: settings.watch.enabled,
    intervalMinutes: settings.watch.intervalMinutes,
    quietHours: settings.watch.quietHours,
    withinQuietHours: isWithinQuietHours(settings.watch.quietHours, at),
    telegramAlerts: settings.watch.telegramAlerts,
    lastRunAt,
    nextRunAt,
    lastError: last?.errorMessage,
    findingsDiscovered: runs.reduce((sum, run) => sum + run.newFindings, 0),
    alertsSent: runs.reduce((sum, run) => sum + run.alertsSent, 0),
    dedupedFindings: runs.reduce((sum, run) => sum + run.dedupedFindings, 0),
    totalCycles: runs.filter((run) => run.status === "completed").length
  };
}

export interface WatchCycleDeps {
  db: JsonDatabase;
  /** Scans all inventoried projects (defaults to RiskRadarService.scanAll). */
  scanAll: () => Promise<unknown>;
  /** Sends an alert; defaults to Telegram. Injected in tests. */
  sendAlert?: (finding: Finding, text: string) => Promise<void>;
  at?: Date;
}

function telegramConfigured(): boolean {
  const chats = (getEnv("TELEGRAM_ALLOWED_CHAT_IDS") ?? "").split(",").map((value) => value.trim()).filter(Boolean);
  return Boolean(getEnv("TELEGRAM_BOT_TOKEN")) && chats.length > 0;
}

async function defaultSendAlert(finding: Finding, text: string): Promise<void> {
  const chats = (getEnv("TELEGRAM_ALLOWED_CHAT_IDS") ?? "").split(",").map((value) => value.trim()).filter(Boolean);
  // Tap to act: "Start remediation" runs the failover ladder (with its own
  // consent gates); "Dismiss" just acknowledges. Never auto-patches.
  const buttons = inlineKeyboard([[
    { text: "🚀 Start remediation", callbackData: telegramCallbackData("w", finding.id, "start") },
    { text: "🔕 Dismiss", callbackData: telegramCallbackData("w", finding.id, "dismiss") }
  ]]);
  for (const chatId of chats) {
    await sendTelegramApproval({ chatId, text, replyMarkup: buttons }).catch(() => undefined);
  }
}

/**
 * Runs one watch cycle. Returns the recorded WatchRun. Does nothing (and does NOT
 * scan) when watch mode is disabled. Never starts remediation automatically.
 */
export async function runWatchCycle(deps: WatchCycleDeps): Promise<WatchRun> {
  const at = deps.at ?? new Date();
  const settings = getSettings(deps.db);
  if (!settings.watch.enabled) {
    return { id: id("watch"), startedAt: at.toISOString(), finishedAt: at.toISOString(), scannedProjects: 0, newFindings: 0, alertsSent: 0, dedupedFindings: 0, status: "skipped_quiet_hours", errorMessage: "watch mode disabled" };
  }
  const run: WatchRun = { id: id("watch"), startedAt: at.toISOString(), scannedProjects: 0, newFindings: 0, alertsSent: 0, dedupedFindings: 0, status: "running" };
  deps.db.update((state) => {
    state.watchRuns = state.watchRuns ?? [];
    state.watchRuns.push(run);
  });

  const beforeIds = new Set(deps.db.read().findings.map((finding) => finding.id));
  const projectCount = deps.db.read().projects.length;
  try {
    await deps.scanAll();
  } catch (error) {
    const failed: WatchRun = { ...run, finishedAt: now(), status: "failed", scannedProjects: projectCount, errorMessage: error instanceof Error ? error.message : String(error) };
    replaceRun(deps.db, failed);
    return failed;
  }

  const state = deps.db.read();
  const newFindings = state.findings.filter((finding) => !beforeIds.has(finding.id));
  const existingAlerts = new Map((state.watchAlerts ?? []).map((alert) => [alert.dedupeKey, alert]));
  const withinQuiet = isWithinQuietHours(settings.watch.quietHours, at);
  const sendAlert = deps.sendAlert ?? defaultSendAlert;
  let alertsSent = 0;
  let deduped = 0;
  const channel: WatchAlert["channel"] = settings.watch.telegramAlerts && telegramConfigured() ? "telegram" : "dashboard";

  for (const finding of newFindings) {
    const key = watchDedupeKey(finding.projectId, finding.vulnerabilityId, finding.packageName, finding.currentVersion);
    if (existingAlerts.has(key)) {
      deduped += 1;
      continue;
    }
    // Quiet hours suppress non-critical alerts; they re-surface in a later cycle.
    if (withinQuiet && finding.riskLevel !== "critical") {
      deduped += 1;
      continue;
    }
    const project = state.projects.find((item) => item.id === finding.projectId);
    const text = [
      "RiskRadar watch alert",
      "",
      `Project: ${project?.name ?? finding.projectId}`,
      `Package: ${finding.packageName}@${finding.currentVersion}`,
      `Risk: ${finding.riskScore}/100 ${finding.riskLevel}`,
      `Fix: ${finding.fixedVersion ? `update to ${finding.fixedVersion}` : "manual review"}`,
      "",
      "New vulnerability found. Start remediation? (review in RiskRadar — watch mode never patches automatically)"
    ].join("\n");
    if (channel === "telegram") await sendAlert(finding, text);
    const alert: WatchAlert = { id: id("walert"), projectId: finding.projectId, dedupeKey: key, findingId: finding.id, packageName: finding.packageName, advisoryId: finding.vulnerabilityId, severity: finding.riskLevel, channel, sentAt: now() };
    existingAlerts.set(key, alert);
    deps.db.update((draft) => {
      draft.watchAlerts = draft.watchAlerts ?? [];
      draft.watchAlerts.push(alert);
    });
    createAuditReceipt(deps.db, { projectId: finding.projectId, actorType: "system", action: "watch.alert", targetType: "finding", targetId: finding.id, outputSummary: { channel, severity: finding.riskLevel, dedupeKey: key } });
    alertsSent += 1;
  }

  const completed: WatchRun = { ...run, finishedAt: now(), status: "completed", scannedProjects: projectCount, newFindings: newFindings.length, alertsSent, dedupedFindings: deduped };
  replaceRun(deps.db, completed);
  createAuditReceipt(deps.db, { actorType: "system", action: "watch.cycle_completed", targetType: "watch_run", targetId: completed.id, outputSummary: { scannedProjects: projectCount, newFindings: newFindings.length, alertsSent, dedupedFindings: deduped, withinQuiet } });
  return completed;
}

function replaceRun(db: JsonDatabase, run: WatchRun): void {
  db.update((state) => {
    const index = (state.watchRuns ?? []).findIndex((item) => item.id === run.id);
    if (index >= 0 && state.watchRuns) state.watchRuns[index] = run;
  });
}
