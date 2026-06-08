import semver from "semver";
import { z } from "zod";
import { getEnv } from "./env";
import { RiskRadarError } from "./errors";
import { redact } from "./redaction";
import { codexStatus } from "./codex";

/**
 * Bring-your-own model provider layer.
 *
 * Only Codex (the workspace editor) and the deterministic fixer are allowed to
 * mutate a repository. The LLM providers (OpenRouter, OpenAI-compatible, Ollama)
 * are advisors: they return a strict JSON remediation plan, which RiskRadar
 * validates and then applies itself. Models never run commands and never edit
 * files directly.
 */
export type AgentProviderId = "codex" | "openrouter" | "openai-compatible" | "anthropic" | "grok" | "ollama" | "deterministic";

export const AGENT_PROVIDER_IDS: AgentProviderId[] = ["codex", "openrouter", "openai-compatible", "anthropic", "grok", "ollama", "deterministic"];

export const LLM_PROVIDER_IDS: AgentProviderId[] = ["openrouter", "openai-compatible", "anthropic", "grok", "ollama"];

/** Resolves the API key for a provider (dedicated key falls back to the shared key). */
function providerApiKey(provider: AgentProviderId): string | undefined {
  if (provider === "grok") return getEnv("RISKRADAR_GROK_API_KEY") ?? getEnv("RISKRADAR_LLM_API_KEY");
  if (provider === "anthropic") return getEnv("RISKRADAR_ANTHROPIC_API_KEY") ?? getEnv("RISKRADAR_LLM_API_KEY");
  return getEnv("RISKRADAR_LLM_API_KEY");
}

export function isLlmProvider(provider: AgentProviderId): boolean {
  return LLM_PROVIDER_IDS.includes(provider);
}

/** Resolves the configured provider. Defaults to Codex; rejects unknown values. */
export function resolveAgentProvider(): AgentProviderId {
  const raw = (getEnv("RISKRADAR_AGENT_PROVIDER") ?? "codex").trim().toLowerCase();
  if ((AGENT_PROVIDER_IDS as string[]).includes(raw)) return raw as AgentProviderId;
  throw new RiskRadarError("unknown_agent_provider", `Unknown RISKRADAR_AGENT_PROVIDER "${raw}".`, { allowed: AGENT_PROVIDER_IDS });
}

interface LlmEndpoint {
  baseUrl?: string;
  requiresKey: boolean;
  defaultModel: string;
  /** Wire format: OpenAI chat-completions, or Anthropic messages API. */
  api: "openai" | "anthropic";
}

function llmEndpoint(provider: AgentProviderId): LlmEndpoint {
  const baseUrl = getEnv("RISKRADAR_LLM_BASE_URL");
  if (provider === "openrouter") {
    return { baseUrl: baseUrl ?? "https://openrouter.ai/api/v1", requiresKey: true, defaultModel: "openai/gpt-4o-mini", api: "openai" };
  }
  if (provider === "grok") {
    // xAI is OpenAI-compatible.
    return { baseUrl: getEnv("RISKRADAR_GROK_BASE_URL") ?? baseUrl ?? "https://api.x.ai/v1", requiresKey: true, defaultModel: "grok-2-latest", api: "openai" };
  }
  if (provider === "anthropic") {
    return { baseUrl: getEnv("RISKRADAR_ANTHROPIC_BASE_URL") ?? "https://api.anthropic.com", requiresKey: true, defaultModel: "claude-3-5-sonnet-latest", api: "anthropic" };
  }
  if (provider === "ollama") {
    return { baseUrl: baseUrl ?? "http://localhost:11434/v1", requiresKey: false, defaultModel: "qwen2.5-coder:7b", api: "openai" };
  }
  // openai-compatible has no safe default base URL.
  return { baseUrl, requiresKey: true, defaultModel: "gpt-4o-mini", api: "openai" };
}

export function agentProviderModel(provider: AgentProviderId): string {
  return getEnv("RISKRADAR_AGENT_MODEL") ?? llmEndpoint(provider).defaultModel;
}

export function llmTimeoutMs(): number {
  return Number(getEnv("RISKRADAR_LLM_TIMEOUT_MS") ?? 120000);
}

export function llmAllowDirectPatch(): boolean {
  // Reserved safety switch. Even when true, RiskRadar still applies the change
  // itself; the model is never given repo-write access.
  return getEnv("RISKRADAR_LLM_ALLOW_DIRECT_PATCH") === "true";
}

/**
 * Throws a clear, codeful error when an LLM provider is missing required config.
 * Never reveals secret values.
 */
export function assertLlmProviderConfigured(provider: AgentProviderId): void {
  if (!isLlmProvider(provider)) {
    throw new RiskRadarError("not_llm_provider", `${provider} is not an LLM advisor provider.`, { provider });
  }
  const endpoint = llmEndpoint(provider);
  if (provider === "openai-compatible" && !endpoint.baseUrl) {
    throw new RiskRadarError("llm_base_url_missing", "Set RISKRADAR_LLM_BASE_URL for the openai-compatible provider.", { requiredEnv: "RISKRADAR_LLM_BASE_URL" });
  }
  if (endpoint.requiresKey && !providerApiKey(provider)) {
    const keyEnv = provider === "grok" ? "RISKRADAR_GROK_API_KEY" : provider === "anthropic" ? "RISKRADAR_ANTHROPIC_API_KEY" : "RISKRADAR_LLM_API_KEY";
    throw new RiskRadarError("llm_api_key_missing", `Set ${keyEnv} for the ${provider} provider.`, { requiredEnv: keyEnv, provider });
  }
}

export type AgentProviderStatus = "configured" | "not_configured" | "unavailable";

export interface AgentProviderReadiness {
  id: AgentProviderId;
  label: string;
  selected: boolean;
  status: AgentProviderStatus;
  /** True only for providers whose model edits the repo directly (Codex). */
  modelEditsRepo: boolean;
  /** Human description of how the change is applied. */
  applyStrategy: "codex-workspace-edit" | "riskradar-applies-plan" | "riskradar-deterministic";
  message: string;
  /** Env var NAMES only — never values. */
  requiredEnv: string[];
}

/**
 * Reports provider readiness for the dashboard/API. Returns env var NAMES only,
 * never secret values, so it is safe to serialize anywhere.
 */
export function agentProviderReadiness(): AgentProviderReadiness[] {
  let selected: AgentProviderId = "codex";
  try {
    selected = resolveAgentProvider();
  } catch {
    selected = "codex";
  }
  const codex = codexStatus();
  const hasKey = Boolean(getEnv("RISKRADAR_LLM_API_KEY"));
  const hasBaseUrl = Boolean(getEnv("RISKRADAR_LLM_BASE_URL"));
  return [
    {
      id: "codex",
      label: "Codex CLI (workspace editor)",
      selected: selected === "codex",
      status: codex.configured ? "configured" : "unavailable",
      modelEditsRepo: true,
      applyStrategy: "codex-workspace-edit",
      message: codex.configured ? "Authenticated Codex CLI edits a disposable, secret-scrubbed workspace directly." : `Codex unavailable: ${codex.message}`,
      requiredEnv: ["CODEX_BIN", "CODEX_ENABLED"]
    },
    {
      id: "openrouter",
      label: "OpenRouter (plan advisor)",
      selected: selected === "openrouter",
      status: hasKey ? "configured" : "not_configured",
      modelEditsRepo: false,
      applyStrategy: "riskradar-applies-plan",
      message: hasKey ? "Returns a strict JSON remediation plan; RiskRadar applies the safe version bump itself." : "Set RISKRADAR_LLM_API_KEY to enable the OpenRouter plan advisor.",
      requiredEnv: ["RISKRADAR_LLM_API_KEY", "RISKRADAR_AGENT_MODEL"]
    },
    {
      id: "openai-compatible",
      label: "OpenAI-compatible (plan advisor)",
      selected: selected === "openai-compatible",
      status: hasKey && hasBaseUrl ? "configured" : "not_configured",
      modelEditsRepo: false,
      applyStrategy: "riskradar-applies-plan",
      message: hasKey && hasBaseUrl ? "Returns a strict JSON remediation plan; RiskRadar applies the safe version bump itself." : "Set RISKRADAR_LLM_BASE_URL and RISKRADAR_LLM_API_KEY to enable an OpenAI-compatible endpoint.",
      requiredEnv: ["RISKRADAR_LLM_BASE_URL", "RISKRADAR_LLM_API_KEY", "RISKRADAR_AGENT_MODEL"]
    },
    {
      id: "anthropic",
      label: "Anthropic Claude (plan advisor)",
      selected: selected === "anthropic",
      status: providerApiKey("anthropic") ? "configured" : "not_configured",
      modelEditsRepo: false,
      applyStrategy: "riskradar-applies-plan",
      message: providerApiKey("anthropic") ? "Returns a strict JSON remediation plan via the Anthropic messages API; RiskRadar applies the change itself." : "Set RISKRADAR_ANTHROPIC_API_KEY (or RISKRADAR_LLM_API_KEY) to enable Anthropic Claude.",
      requiredEnv: ["RISKRADAR_ANTHROPIC_API_KEY", "RISKRADAR_AGENT_MODEL"]
    },
    {
      id: "grok",
      label: "Grok / xAI (plan advisor)",
      selected: selected === "grok",
      status: providerApiKey("grok") ? "configured" : "not_configured",
      modelEditsRepo: false,
      applyStrategy: "riskradar-applies-plan",
      message: providerApiKey("grok") ? "Returns a strict JSON remediation plan via the xAI OpenAI-compatible API; RiskRadar applies the change itself." : "Set RISKRADAR_GROK_API_KEY (or RISKRADAR_LLM_API_KEY) to enable Grok / xAI.",
      requiredEnv: ["RISKRADAR_GROK_API_KEY", "RISKRADAR_AGENT_MODEL"]
    },
    {
      id: "ollama",
      label: "Ollama / local (plan advisor)",
      selected: selected === "ollama",
      status: "configured",
      modelEditsRepo: false,
      applyStrategy: "riskradar-applies-plan",
      message: "Assumes a local Ollama OpenAI-compatible endpoint (RISKRADAR_LLM_BASE_URL, default http://localhost:11434/v1). Verify with verify:ollama-live.",
      requiredEnv: ["RISKRADAR_LLM_BASE_URL", "RISKRADAR_AGENT_MODEL"]
    },
    {
      id: "deterministic",
      label: "Deterministic npm fixer",
      selected: selected === "deterministic",
      status: "configured",
      modelEditsRepo: false,
      applyStrategy: "riskradar-deterministic",
      message: "No model. Updates the direct dependency to the OSV-known fixed version and validates in a disposable workspace.",
      requiredEnv: []
    }
  ];
}

export const REMEDIATION_PLAN_SYSTEM_PROMPT = `You are RiskRadar's dependency remediation planner.
You do NOT have access to the repository and you cannot run commands.
Return ONLY a strict JSON object (no markdown, no prose, no code fences) of exactly this shape:
{"action":"update_dependency","ecosystem":"npm","file":"package.json","packageName":"<name>","fromVersion":"<current>","toVersion":"<fixed>","summary":"<one short sentence>"}
Rules:
- "toVersion" MUST be the smallest safe fixed version provided in the context.
- Do not include any other keys. Never include commands, scripts, shell, or install instructions.
- Never reference any file other than package.json.
- Do not propose a major-version upgrade.`;

const DANGEROUS_PLAN_KEYS = ["command", "commands", "cmd", "run", "script", "scripts", "exec", "shell", "install", "postinstall", "bash", "sh"];

const remediationPlanSchema = z.object({
  action: z.literal("update_dependency"),
  ecosystem: z.literal("npm"),
  file: z.literal("package.json"),
  packageName: z.string().min(1),
  fromVersion: z.string().min(1),
  toVersion: z.string().min(1),
  summary: z.string().min(1)
});

export type RemediationPlan = z.infer<typeof remediationPlanSchema>;

export interface RemediationPlanExpectation {
  packageName: string;
  fromVersion: string;
  fixedVersion?: string;
}

function stripCodeFences(raw: string): string {
  const trimmed = raw.trim();
  const fenced = trimmed.match(/^```(?:json)?\s*([\s\S]*?)\s*```$/i);
  return (fenced?.[1] ?? trimmed).trim();
}

function cleanVersion(value: string): string | null {
  return semver.valid(value) ?? semver.valid(semver.coerce(value) ?? "");
}

/**
 * Parses and strictly validates a model's remediation plan. Rejects: invalid
 * JSON, wrong action, any file other than package.json, arbitrary command
 * fields, package mismatches, invalid/downgrade/major-bump versions, and
 * versions below the known safe fixed version.
 */
export function parseRemediationPlan(raw: string, expected: RemediationPlanExpectation): RemediationPlan {
  let parsed: unknown;
  try {
    parsed = JSON.parse(stripCodeFences(raw));
  } catch {
    throw new RiskRadarError("plan_invalid_json", "Model did not return valid JSON.", { sample: redact(raw).slice(0, 200) });
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new RiskRadarError("plan_invalid_schema", "Model plan was not a JSON object.");
  }
  const record = parsed as Record<string, unknown>;
  const dangerous = Object.keys(record).find((key) => DANGEROUS_PLAN_KEYS.includes(key.toLowerCase()));
  if (dangerous) {
    throw new RiskRadarError("plan_arbitrary_command", "Model plan included a command/script field, which is not allowed.", { key: dangerous });
  }
  if (typeof record.file === "string" && record.file !== "package.json") {
    throw new RiskRadarError("plan_forbidden_file", "Model plan targeted a file other than package.json.", { file: record.file });
  }
  const result = remediationPlanSchema.safeParse(record);
  if (!result.success) {
    throw new RiskRadarError("plan_invalid_schema", "Model plan did not match the required schema.", { issues: result.error.issues.map((issue) => issue.path.join(".")) });
  }
  const plan = result.data;
  if (plan.packageName !== expected.packageName) {
    throw new RiskRadarError("plan_package_mismatch", "Model plan targeted a different package than the finding.", { expected: expected.packageName, got: plan.packageName });
  }
  const from = cleanVersion(expected.fromVersion);
  const to = cleanVersion(plan.toVersion);
  if (!to) {
    throw new RiskRadarError("plan_invalid_version", "Model plan proposed an invalid target version.", { toVersion: plan.toVersion });
  }
  if (from && semver.lte(to, from)) {
    throw new RiskRadarError("plan_not_an_upgrade", "Model plan did not propose an upgrade.", { fromVersion: expected.fromVersion, toVersion: plan.toVersion });
  }
  if (from && semver.major(to) > semver.major(from)) {
    throw new RiskRadarError("plan_major_upgrade", "Model plan proposed a major-version upgrade, which is blocked.", { fromVersion: expected.fromVersion, toVersion: plan.toVersion });
  }
  const fixed = expected.fixedVersion ? cleanVersion(expected.fixedVersion) : null;
  if (fixed && semver.lt(to, fixed)) {
    throw new RiskRadarError("plan_below_fixed_version", "Model plan target is below the known safe fixed version.", { fixedVersion: expected.fixedVersion, toVersion: plan.toVersion });
  }
  return plan;
}

export interface LlmChatRequest {
  url: string;
  headers: Record<string, string>;
  body: {
    model: string;
    temperature: number;
    stream: false;
    response_format: { type: "json_object" };
    messages: Array<{ role: "system" | "user"; content: string }>;
  };
}

/** Builds an OpenAI-compatible chat-completions request. Pure and testable. */
export function buildLlmChatRequest(provider: AgentProviderId, context: unknown): LlmChatRequest {
  const endpoint = llmEndpoint(provider);
  if (!endpoint.baseUrl) {
    throw new RiskRadarError("llm_base_url_missing", "No base URL resolved for the provider.", { provider });
  }
  const apiKey = providerApiKey(provider);
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (apiKey) headers.authorization = `Bearer ${apiKey}`;
  if (provider === "openrouter") {
    headers["HTTP-Referer"] = getEnv("APP_PUBLIC_URL") ?? "https://github.com/riskradar";
    headers["X-Title"] = "RiskRadar";
  }
  return {
    url: `${endpoint.baseUrl.replace(/\/$/, "")}/chat/completions`,
    headers,
    body: {
      model: agentProviderModel(provider),
      temperature: 0,
      stream: false,
      response_format: { type: "json_object" },
      messages: [
        { role: "system", content: REMEDIATION_PLAN_SYSTEM_PROMPT },
        { role: "user", content: JSON.stringify(context) }
      ]
    }
  };
}

export interface AnthropicRequest {
  url: string;
  headers: Record<string, string>;
  body: {
    model: string;
    max_tokens: number;
    system: string;
    messages: Array<{ role: "user"; content: string }>;
  };
}

/** Builds an Anthropic messages-API request. Pure and testable. */
export function buildAnthropicRequest(context: unknown): AnthropicRequest {
  const endpoint = llmEndpoint("anthropic");
  const apiKey = providerApiKey("anthropic");
  const headers: Record<string, string> = {
    "content-type": "application/json",
    "anthropic-version": getEnv("RISKRADAR_ANTHROPIC_VERSION") ?? "2023-06-01"
  };
  if (apiKey) headers["x-api-key"] = apiKey;
  return {
    url: `${endpoint.baseUrl!.replace(/\/$/, "")}/v1/messages`,
    headers,
    body: {
      model: agentProviderModel("anthropic"),
      max_tokens: 1024,
      system: REMEDIATION_PLAN_SYSTEM_PROMPT,
      messages: [{ role: "user", content: JSON.stringify(context) }]
    }
  };
}

export interface RemediationPlanResult {
  plan: RemediationPlan;
  raw: string;
  provider: AgentProviderId;
  model: string;
}

/** Calls the configured LLM provider and returns a validated remediation plan. */
export async function requestRemediationPlan(
  provider: AgentProviderId,
  context: unknown,
  expected: RemediationPlanExpectation
): Promise<RemediationPlanResult> {
  assertLlmProviderConfigured(provider);
  const isAnthropic = llmEndpoint(provider).api === "anthropic";
  const request = isAnthropic ? buildAnthropicRequest(context) : buildLlmChatRequest(provider, context);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), llmTimeoutMs());
  let response: Response;
  try {
    response = await fetch(request.url, {
      method: "POST",
      headers: request.headers,
      body: JSON.stringify(request.body),
      signal: controller.signal
    });
  } catch (error) {
    const aborted = error instanceof Error && error.name === "AbortError";
    throw new RiskRadarError(aborted ? "llm_timeout" : "llm_request_failed", aborted ? `LLM request timed out after ${llmTimeoutMs()}ms.` : `LLM request failed: ${redact(error instanceof Error ? error.message : String(error))}`, { provider });
  } finally {
    clearTimeout(timer);
  }
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new RiskRadarError("llm_request_failed", `LLM provider returned HTTP ${response.status}.`, { provider, body: redact(text).slice(0, 300) });
  }
  const data = await response.json().catch(() => ({})) as { choices?: Array<{ message?: { content?: string } }>; content?: Array<{ text?: string }> };
  // Anthropic returns content[].text; OpenAI-compatible returns choices[].message.content.
  const content = isAnthropic ? data.content?.[0]?.text : data.choices?.[0]?.message?.content;
  if (!content || content.trim().length === 0) {
    throw new RiskRadarError("llm_empty_response", "LLM provider returned an empty message.", { provider });
  }
  const plan = parseRemediationPlan(content, expected);
  return { plan, raw: redact(content).slice(0, 2000), provider, model: agentProviderModel(provider) };
}

export interface AgentRemediationOutcome {
  status: "completed" | "timeout" | "failed" | "not_configured" | "no_changes";
  /** Real completion: ready state with detected file changes. Never faked. */
  completed: boolean;
  shouldFallback: boolean;
}

/**
 * Generic, provider-agnostic outcome classifier. A job is only "completed" when
 * it reached a ready state with real detected file changes; everything else
 * falls back to deterministic remediation and is reported honestly.
 */
export function classifyAgentRemediation(job: { status?: string; errorCode?: string; changedFiles?: string[] } | undefined): AgentRemediationOutcome {
  const code = job?.errorCode ?? "";
  const changed = (job?.changedFiles ?? []).length > 0;
  if (code === "llm_timeout" || code === "codex_timeout" || code.endsWith("_timeout")) {
    return { status: "timeout", completed: false, shouldFallback: true };
  }
  if (/not_configured|unavailable|api_key_missing|base_url_missing/.test(code)) {
    return { status: "not_configured", completed: false, shouldFallback: true };
  }
  if (code.endsWith("_no_changes")) {
    return { status: "no_changes", completed: false, shouldFallback: true };
  }
  const ready = job?.status === "pr_ready" || job?.status === "approval_sent";
  if (ready && changed) {
    return { status: "completed", completed: true, shouldFallback: false };
  }
  return { status: "failed", completed: false, shouldFallback: true };
}
