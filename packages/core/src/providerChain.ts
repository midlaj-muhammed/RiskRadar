import { getEnv } from "./env";
import { redact } from "./redaction";
import { codexStatus } from "./codex";
import type { FailoverSettings } from "./types";

/**
 * Fast provider failover ladder.
 *
 * Readiness is cached (TTL) so we do not re-probe every provider on every
 * remediation. Unconfigured providers are skipped instantly with no network
 * call. Switching to a lower-trust provider (local model or deterministic) can
 * require explicit Telegram consent. Nothing here ever lets a non-Codex model
 * edit a repo — providers only return plans that RiskRadar applies.
 */
export type ProviderRuntimeStatus =
  | "ready"
  | "not_configured"
  | "quota_limited"
  | "rate_limited"
  | "auth_failed"
  | "model_missing"
  | "endpoint_unreachable"
  | "timeout"
  | "invalid_response"
  | "failed"
  | "completed";

export type ProviderTrust = "codex" | "cloud" | "local" | "deterministic";

export const PROVIDER_AUDIT_ACTIONS = {
  chainStarted: "provider_chain_started",
  readinessChecked: "provider_readiness_checked",
  attemptStarted: "provider_attempt_started",
  attemptFailed: "provider_attempt_failed",
  attemptCompleted: "provider_attempt_completed",
  consentRequested: "provider_failover_consent_requested",
  consentApproved: "provider_failover_consent_approved",
  consentRejected: "provider_failover_consent_rejected",
  localModelUsed: "local_model_used",
  deterministicUsed: "deterministic_fallback_used"
} as const;

export function providerTrust(provider: string): ProviderTrust {
  if (provider === "codex") return "codex";
  if (provider === "ollama") return "local";
  if (provider === "deterministic") return "deterministic";
  return "cloud";
}

const TRUST_RANK: Record<ProviderTrust, number> = { codex: 3, cloud: 2, local: 1, deterministic: 0 };

export function isLowerTrust(candidate: string, reference: string): boolean {
  return TRUST_RANK[providerTrust(candidate)] < TRUST_RANK[providerTrust(reference)];
}

/** Maps an error code or message to a provider runtime status. */
export function classifyProviderError(codeOrMessage: string): ProviderRuntimeStatus {
  const text = codeOrMessage.toLowerCase();
  if (/quota|usage limit|insufficient_quota|credits/.test(text)) return "quota_limited";
  if (/rate.?limit|too many requests|\b429\b/.test(text)) return "rate_limited";
  if (/unauthor|forbidden|auth|api_key_missing|\b401\b|\b403\b/.test(text)) return "auth_failed";
  if (/model.?missing|model_not_found|no such model|unknown model/.test(text)) return "model_missing";
  if (/timeout|timed out|etimedout|abort/.test(text)) return "timeout";
  if (/not_configured|base_url_missing/.test(text)) return "not_configured";
  if (/unreachable|econnrefused|enotfound|connect|endpoint/.test(text)) return "endpoint_unreachable";
  if (/invalid|parse|schema|plan_/.test(text)) return "invalid_response";
  return "failed";
}

export interface ProviderReadiness {
  provider: string;
  model?: string;
  status: ProviderRuntimeStatus;
  trust: ProviderTrust;
  lastCheckedAt: string;
  latencyMs?: number;
  failureReason?: string;
  /** True when a local model endpoint answered but has no warm model loaded. */
  cold?: boolean;
}

// ---------- readiness cache ----------

const readinessCache = new Map<string, ProviderReadiness>();

export function clearReadinessCache(): void {
  readinessCache.clear();
}

export function getCachedReadiness(provider: string, ttlMs: number, atMs = Date.now()): ProviderReadiness | undefined {
  const entry = readinessCache.get(provider);
  if (!entry) return undefined;
  if (atMs - new Date(entry.lastCheckedAt).getTime() > ttlMs) return undefined;
  return entry;
}

export function setCachedReadiness(entry: ProviderReadiness): void {
  readinessCache.set(entry.provider, entry);
}

export function readinessCacheAgeMs(provider: string, atMs = Date.now()): number | undefined {
  const entry = readinessCache.get(provider);
  return entry ? atMs - new Date(entry.lastCheckedAt).getTime() : undefined;
}

// ---------- configuration probing (no network) ----------

function providerConfigured(provider: string): { configured: boolean; reason?: string } {
  if (provider === "codex") {
    const status = codexStatus();
    return { configured: status.configured, reason: status.configured ? undefined : status.message };
  }
  if (provider === "deterministic") return { configured: true };
  if (provider === "openrouter") {
    return getEnv("RISKRADAR_LLM_API_KEY") ? { configured: true } : { configured: false, reason: "RISKRADAR_LLM_API_KEY missing" };
  }
  if (provider === "openai-compatible") {
    if (!getEnv("RISKRADAR_LLM_BASE_URL")) return { configured: false, reason: "RISKRADAR_LLM_BASE_URL missing" };
    return getEnv("RISKRADAR_LLM_API_KEY") ? { configured: true } : { configured: false, reason: "RISKRADAR_LLM_API_KEY missing" };
  }
  if (provider === "grok") {
    return getEnv("RISKRADAR_GROK_API_KEY") ?? getEnv("RISKRADAR_LLM_API_KEY") ? { configured: true } : { configured: false, reason: "RISKRADAR_GROK_API_KEY missing" };
  }
  if (provider === "anthropic") {
    return getEnv("RISKRADAR_ANTHROPIC_API_KEY") ?? getEnv("RISKRADAR_LLM_API_KEY") ? { configured: true } : { configured: false, reason: "RISKRADAR_ANTHROPIC_API_KEY missing" };
  }
  if (provider === "ollama") return { configured: true };
  return { configured: false, reason: `${provider} provider is not implemented` };
}

function ollamaBaseUrl(): string {
  return (getEnv("RISKRADAR_LLM_BASE_URL") ?? "http://localhost:11434/v1").replace(/\/$/, "");
}

async function fetchWithTimeout(url: string, timeoutMs: number, init: RequestInit = {}): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal });
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Checks one provider's readiness. Unconfigured providers return immediately
 * with no network call. Local/cloud endpoints get a short, timeout-bounded probe
 * (never a full generation).
 */
export async function checkProviderReadiness(provider: string, options: { timeoutMs?: number; model?: string } = {}): Promise<ProviderReadiness> {
  const trust = providerTrust(provider);
  const started = Date.now();
  const base = (status: ProviderRuntimeStatus, extra: Partial<ProviderReadiness> = {}): ProviderReadiness => ({
    provider,
    model: options.model,
    status,
    trust,
    lastCheckedAt: new Date().toISOString(),
    latencyMs: Date.now() - started,
    ...extra
  });

  const config = providerConfigured(provider);
  if (!config.configured) return base("not_configured", { failureReason: config.reason });
  if (provider === "codex" || provider === "deterministic") return base("ready");

  const timeoutMs = options.timeoutMs ?? Number(getEnv("RISKRADAR_PROVIDER_READINESS_TIMEOUT_MS") ?? 3000);
  try {
    if (provider === "ollama") {
      const response = await fetchWithTimeout(`${ollamaBaseUrl().replace(/\/v1$/, "")}/api/tags`, timeoutMs);
      if (!response.ok) return base("endpoint_unreachable", { failureReason: `HTTP ${response.status}` });
      const body = await response.json().catch(() => ({})) as { models?: Array<{ name?: string }> };
      const names = (body.models ?? []).map((m) => m.name ?? "");
      const cold = options.model ? !names.some((name) => name === options.model || name.startsWith(`${options.model}`)) : false;
      return base("ready", { cold });
    }
    if (provider === "anthropic") {
      const baseUrl = (getEnv("RISKRADAR_ANTHROPIC_BASE_URL") ?? "https://api.anthropic.com").replace(/\/$/, "");
      const key = getEnv("RISKRADAR_ANTHROPIC_API_KEY") ?? getEnv("RISKRADAR_LLM_API_KEY");
      const response = await fetchWithTimeout(`${baseUrl}/v1/models`, timeoutMs, { headers: { "x-api-key": key ?? "", "anthropic-version": getEnv("RISKRADAR_ANTHROPIC_VERSION") ?? "2023-06-01" } });
      if (response.status === 401 || response.status === 403) return base("auth_failed", { failureReason: `HTTP ${response.status}` });
      if (!response.ok) return base("endpoint_unreachable", { failureReason: `HTTP ${response.status}` });
      return base("ready");
    }
    // openrouter / grok / openai-compatible: quick OpenAI-style model list probe.
    const baseUrl = (provider === "openrouter"
      ? getEnv("RISKRADAR_LLM_BASE_URL") ?? "https://openrouter.ai/api/v1"
      : provider === "grok"
        ? getEnv("RISKRADAR_GROK_BASE_URL") ?? getEnv("RISKRADAR_LLM_BASE_URL") ?? "https://api.x.ai/v1"
        : getEnv("RISKRADAR_LLM_BASE_URL")!).replace(/\/$/, "");
    const headers: Record<string, string> = {};
    const key = provider === "grok" ? getEnv("RISKRADAR_GROK_API_KEY") ?? getEnv("RISKRADAR_LLM_API_KEY") : getEnv("RISKRADAR_LLM_API_KEY");
    if (key) headers.authorization = `Bearer ${key}`;
    const response = await fetchWithTimeout(`${baseUrl}/models`, timeoutMs, { headers });
    if (response.status === 401 || response.status === 403) return base("auth_failed", { failureReason: `HTTP ${response.status}` });
    if (!response.ok) return base("endpoint_unreachable", { failureReason: `HTTP ${response.status}` });
    return base("ready");
  } catch (error) {
    const aborted = error instanceof Error && error.name === "AbortError";
    return base(aborted ? "timeout" : "endpoint_unreachable", { failureReason: redact(error instanceof Error ? error.message : String(error)) });
  }
}

/**
 * Checks readiness for a chain. Skips unconfigured providers instantly (no
 * network), runs the remaining probes in parallel, and uses/refreshes the cache.
 */
export async function checkChainReadiness(chain: string[], settings: Pick<FailoverSettings, "readinessTimeoutMs" | "readinessCacheTtlMs">, options: { model?: string; forceRefresh?: boolean } = {}): Promise<ProviderReadiness[]> {
  const results = await Promise.all(chain.map(async (provider) => {
    if (!options.forceRefresh) {
      const cached = getCachedReadiness(provider, settings.readinessCacheTtlMs);
      if (cached) return cached;
    }
    // Instant skip for unconfigured providers — no probe, no network.
    const config = providerConfigured(provider);
    if (!config.configured) {
      const entry: ProviderReadiness = { provider, status: "not_configured", trust: providerTrust(provider), lastCheckedAt: new Date().toISOString(), latencyMs: 0, failureReason: config.reason };
      setCachedReadiness(entry);
      return entry;
    }
    const entry = await checkProviderReadiness(provider, { timeoutMs: settings.readinessTimeoutMs, model: options.model });
    setCachedReadiness(entry);
    return entry;
  }));
  return results;
}

// ---------- failover decision ----------

export interface FailoverDecision {
  action: "use_provider" | "request_consent" | "use_deterministic" | "stop";
  provider?: string;
  trust?: ProviderTrust;
  reason: string;
}

/**
 * Decides the next step after a provider attempt fails. Cloud→cloud failover is
 * allowed when enabled; moving to a local model or deterministic fallback in
 * "ask" mode requires consent unless a per-repo always-allow policy exists.
 */
export function decideFailover(input: {
  chain: string[];
  readiness: Record<string, ProviderRuntimeStatus>;
  failedProvider: string;
  settings: FailoverSettings;
  repoAlwaysAllowLocal?: boolean;
}): FailoverDecision {
  const { chain, readiness, failedProvider, settings } = input;
  if (settings.mode === "disabled") {
    return { action: "use_deterministic", reason: "Failover disabled; using deterministic fallback." };
  }
  const startIndex = chain.indexOf(failedProvider);
  const candidates = startIndex >= 0 ? chain.slice(startIndex + 1) : chain;

  for (const candidate of candidates) {
    if (candidate === "deterministic") {
      if (settings.mode === "ask" && settings.requireConsentForLowerTrust) {
        return { action: "request_consent", provider: "deterministic", trust: "deterministic", reason: "Consent required before using the deterministic fallback." };
      }
      return { action: "use_deterministic", reason: "Deterministic fallback is the next ready option." };
    }
    if (readiness[candidate] !== "ready") continue;
    const trust = providerTrust(candidate);
    if (trust === "cloud") {
      if (!settings.allowCloudFailover) continue;
      return { action: "use_provider", provider: candidate, trust, reason: `Cloud failover to ready provider ${candidate}.` };
    }
    if (trust === "local") {
      if (input.repoAlwaysAllowLocal) {
        return { action: "use_provider", provider: candidate, trust, reason: `Repo policy always allows local model ${candidate}.` };
      }
      if (settings.mode === "automatic") {
        if (settings.allowLocalFailover) return { action: "use_provider", provider: candidate, trust, reason: `Automatic local failover to ${candidate}.` };
        continue;
      }
      // ask mode
      if (settings.requireConsentForLowerTrust) {
        return { action: "request_consent", provider: candidate, trust, reason: `Consent required before using local model ${candidate}.` };
      }
      if (settings.allowLocalFailover) return { action: "use_provider", provider: candidate, trust, reason: `Local failover to ${candidate} (consent not required).` };
      continue;
    }
  }
  // Nothing ready in the chain — safe deterministic fallback.
  if (settings.mode === "ask" && settings.requireConsentForLowerTrust) {
    return { action: "request_consent", provider: "deterministic", trust: "deterministic", reason: "No ready provider remaining; consent required before deterministic fallback." };
  }
  return { action: "use_deterministic", reason: "No ready provider remaining; using deterministic fallback." };
}

const STATUS_LABEL: Record<ProviderRuntimeStatus, string> = {
  ready: "ready",
  not_configured: "not configured",
  quota_limited: "failed — usage limit",
  rate_limited: "failed — rate limited",
  auth_failed: "failed — auth",
  model_missing: "model missing",
  endpoint_unreachable: "endpoint unreachable",
  timeout: "timeout",
  invalid_response: "invalid response",
  failed: "failed",
  completed: "completed"
};

/** Builds the Telegram consent message body shown before a lower-trust provider runs. */
export function buildFailoverConsentMessage(readiness: ProviderReadiness[], candidate: ProviderReadiness): string {
  const lines = ["RiskRadar provider failover needed.", ""];
  for (const entry of readiness) {
    const latency = entry.status === "ready" && entry.latencyMs !== undefined ? `, ${entry.latencyMs}ms` : "";
    const name = entry.model ? `${entry.provider} ${entry.model}` : entry.provider;
    lines.push(`${name}: ${STATUS_LABEL[entry.status]}${latency}${entry.failureReason ? ` (${entry.failureReason})` : ""}`);
  }
  lines.push("");
  if (candidate.trust === "deterministic") {
    lines.push("Allow RiskRadar's deterministic fixer to update the dependency to the known fixed version?");
  } else {
    const cold = candidate.cold ? " Local model available but cold; estimated slow start." : "";
    lines.push(`Allow local model ${candidate.model ?? candidate.provider} to generate a strict JSON patch plan?${cold}`);
  }
  lines.push("RiskRadar will apply changes itself, run validation, create a draft PR, and ask for final approval.");
  return lines.join("\n");
}

export const FAILOVER_CONSENT_OPTIONS = ["allow_once", "always_allow_repo", "use_deterministic", "reject"] as const;
export type FailoverConsentOption = (typeof FAILOVER_CONSENT_OPTIONS)[number];
