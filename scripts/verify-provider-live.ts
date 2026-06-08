import { cpSync, existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  JsonDatabase,
  RiskRadarService,
  type AgentProviderId,
  agentProviderReadiness,
  assertLlmProviderConfigured,
  classifyAgentRemediation,
  createAuditReceipt
} from "../packages/core/src/index.ts";
import { loadDotenvFile, optionalEnv, safeJson } from "./live-utils.ts";

loadDotenvFile();

const provider = (process.argv[2] ?? "").trim() as AgentProviderId;
const SUPPORTED: AgentProviderId[] = ["openrouter", "openai-compatible", "ollama"];

function readiness(id: AgentProviderId) {
  return agentProviderReadiness().find((entry) => entry.id === id);
}

function skip(reason: string, status: string): never {
  // Honest skip: the provider is not configured/reachable here. Never faked.
  console.log(safeJson({ ok: true, provider, ran: false, status, reason, readiness: readiness(provider) }));
  process.exit(0);
}

async function reachable(url: string): Promise<boolean> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 2500);
  try {
    await fetch(url, { signal: controller.signal });
    return true;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

async function main() {
  if (!SUPPORTED.includes(provider)) {
    console.error(safeJson({ ok: false, error: `Usage: verify-provider-live <${SUPPORTED.join("|")}>` }));
    process.exit(2);
  }

  // Configuration gate — skip honestly when keys/base URL are absent.
  try {
    assertLlmProviderConfigured(provider);
  } catch (error) {
    skip(error instanceof Error ? error.message : String(error), "not_configured");
  }

  // For local Ollama, also confirm the endpoint is actually reachable.
  if (provider === "ollama") {
    const baseUrl = optionalEnv("RISKRADAR_LLM_BASE_URL") ?? "http://localhost:11434/v1";
    if (!(await reachable(baseUrl.replace(/\/v1\/?$/, "")))) {
      skip(`No Ollama endpoint reachable at ${baseUrl}.`, "unavailable");
    }
  }

  const root = path.join(os.tmpdir(), `riskradar-${provider}-live-${Date.now()}`);
  const fixture = path.join(root, "fixture");
  cpSync(path.join(process.cwd(), "tests", "fixtures", "vulnerable-npm-project"), fixture, { recursive: true });
  writeFileSync(path.join(fixture, ".env"), "SECRET_SHOULD_NOT_COPY=super-secret-value");
  process.env.RISKRADAR_DATA_FILE = path.join(root, "db.json");
  process.env.RISKRADAR_LOG_DIR = path.join(root, "logs");
  process.env.RISKRADAR_WORKSPACE_DIR = path.join(root, "workspaces");
  process.env.RISKRADAR_LOCAL_ROOTS = root;
  process.env.RISKRADAR_RETAIN_WORKSPACES = "true";
  const previousAllowedChats = process.env.TELEGRAM_ALLOWED_CHAT_IDS;
  process.env.TELEGRAM_ALLOWED_CHAT_IDS = "";
  try {
    const db = new JsonDatabase(process.env.RISKRADAR_DATA_FILE);
    const service = new RiskRadarService(db);
    const project = await service.createProject({ sourceType: "local", localPath: fixture, name: `riskradar-${provider}-live-fixture` });
    await service.scanProject(project.id);
    const finding = db.read().findings.find((item) => item.projectId === project.id && item.status === "fix_available" && item.fixedVersion);
    if (!finding) throw new Error("No fixable fixture finding found for provider live verification.");

    const job = await service.startRemediation(finding.id, provider);
    const outcome = classifyAgentRemediation(job);
    const workspace = job.workspacePath;
    const secretCopied = workspace ? existsSync(path.join(workspace, ".env")) : false;

    let fallbackJob: Awaited<ReturnType<RiskRadarService["startRemediation"]>> | undefined;
    if (outcome.shouldFallback) {
      fallbackJob = await service.startRemediation(finding.id, "deterministic-npm");
    }
    const fallbackOk = fallbackJob ? fallbackJob.status === "pr_ready" || fallbackJob.status === "approval_sent" : false;

    createAuditReceipt(db, {
      projectId: project.id,
      actorType: "system",
      agent: provider,
      action: "verification.provider_live",
      targetType: "remediation_job",
      targetId: job.id,
      changedFiles: job.changedFiles,
      outputSummary: { provider, providerStatus: outcome.status, completed: outcome.completed, fallbackStatus: fallbackJob?.status, secretCopied }
    });

    const ok = !secretCopied && (outcome.completed || (outcome.shouldFallback && fallbackOk));
    console.log(safeJson({
      ok,
      provider,
      ran: true,
      providerStatus: outcome.status,
      providerCompleted: outcome.completed,
      status: job.status,
      errorCode: job.errorCode,
      changedFiles: job.changedFiles,
      patchPath: job.patchPath,
      secretFilesCopied: secretCopied,
      usedDeterministicFallback: Boolean(fallbackJob),
      deterministicFallback: fallbackJob ? { status: fallbackJob.status, changedFiles: fallbackJob.changedFiles, patchPath: fallbackJob.patchPath } : undefined
    }));
    if (!ok) process.exit(1);
  } finally {
    if (previousAllowedChats === undefined) delete process.env.TELEGRAM_ALLOWED_CHAT_IDS;
    else process.env.TELEGRAM_ALLOWED_CHAT_IDS = previousAllowedChats;
    if (existsSync(path.join(root, "logs"))) {
      writeFileSync(path.join(root, "README.txt"), "RiskRadar retained this provider verification workspace for inspection.\n");
      readFileSync(path.join(root, "README.txt"), "utf8");
    } else {
      rmSync(root, { recursive: true, force: true });
    }
  }
}

main().catch((error) => {
  console.error(safeJson({ ok: false, provider, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
