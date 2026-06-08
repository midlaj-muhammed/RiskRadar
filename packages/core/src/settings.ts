import { JsonDatabase } from "./database";
import { getEnv } from "./env";
import type { FailoverMode, FailoverSettings, RiskRadarSettings, RepoFailoverPolicy, StoredSettings, WatchSettings } from "./types";

export type { RiskRadarSettings } from "./types";

const DEFAULT_CHAIN = ["codex", "openrouter", "anthropic", "grok", "openai-compatible", "ollama", "deterministic"];

function envBool(name: string, fallback: boolean): boolean {
  const value = getEnv(name);
  if (value === undefined) return fallback;
  return value.toLowerCase() === "true";
}

function envNum(name: string, fallback: number): number {
  const value = Number(getEnv(name));
  return Number.isFinite(value) && value > 0 ? value : fallback;
}

function envMode(name: string, fallback: FailoverMode): FailoverMode {
  const value = (getEnv(name) ?? "").toLowerCase();
  return value === "ask" || value === "automatic" || value === "disabled" ? value : fallback;
}

/** Safe-by-default settings derived from env. The DB stores only overrides. */
export function envDefaultSettings(): RiskRadarSettings {
  const watch: WatchSettings = {
    enabled: envBool("RISKRADAR_WATCH_ENABLED", false),
    intervalMinutes: envNum("RISKRADAR_WATCH_INTERVAL_MINUTES", 60),
    quietHours: getEnv("RISKRADAR_QUIET_HOURS"),
    telegramAlerts: envBool("RISKRADAR_WATCH_TELEGRAM_ALERTS", true)
  };
  const chainRaw = getEnv("RISKRADAR_PROVIDER_CHAIN");
  const failover: FailoverSettings = {
    mode: envMode("RISKRADAR_PROVIDER_FAILOVER_MODE", "ask"),
    chain: chainRaw ? chainRaw.split(",").map((entry) => entry.trim()).filter(Boolean) : [...DEFAULT_CHAIN],
    allowCloudFailover: envBool("RISKRADAR_ALLOW_CLOUD_MODEL_FAILOVER", true),
    allowLocalFailover: envBool("RISKRADAR_ALLOW_LOCAL_MODEL_FAILOVER", false),
    requireConsentForLowerTrust: envBool("RISKRADAR_REQUIRE_CONSENT_FOR_LOWER_TRUST_PROVIDER", true),
    fast: envBool("RISKRADAR_FAST_FAILOVER", true),
    maxAttempts: envNum("RISKRADAR_PROVIDER_CHAIN_MAX_ATTEMPTS", 3),
    readinessTimeoutMs: envNum("RISKRADAR_PROVIDER_READINESS_TIMEOUT_MS", 3000),
    attemptTimeoutMs: envNum("RISKRADAR_PROVIDER_ATTEMPT_TIMEOUT_MS", 30000),
    readinessCacheTtlMs: envNum("RISKRADAR_PROVIDER_READINESS_CACHE_TTL_MS", 600000)
  };
  return { watch, failover, repoPolicies: {}, scannerToggles: {} };
}

function mergeSettings(defaults: RiskRadarSettings, stored: StoredSettings | undefined): RiskRadarSettings {
  return {
    watch: { ...defaults.watch, ...(stored?.watch ?? {}) },
    failover: {
      ...defaults.failover,
      ...(stored?.failover ?? {}),
      chain: stored?.failover?.chain ?? defaults.failover.chain
    },
    repoPolicies: { ...defaults.repoPolicies, ...(stored?.repoPolicies ?? {}) },
    scannerToggles: { ...defaults.scannerToggles, ...(stored?.scannerToggles ?? {}) }
  };
}

/** Resolved settings: env defaults overlaid with persisted DB overrides. */
export function getSettings(db = new JsonDatabase()): RiskRadarSettings {
  return mergeSettings(envDefaultSettings(), db.read().settings);
}

/** Persists a partial settings override and returns the resolved settings. */
export function updateSettings(db: JsonDatabase, patch: StoredSettings): RiskRadarSettings {
  db.update((state) => {
    const current = state.settings ?? {};
    state.settings = {
      watch: { ...(current.watch ?? {}), ...(patch.watch ?? {}) },
      failover: { ...(current.failover ?? {}), ...(patch.failover ?? {}) },
      repoPolicies: { ...(current.repoPolicies ?? {}), ...(patch.repoPolicies ?? {}) },
      scannerToggles: { ...(current.scannerToggles ?? {}), ...(patch.scannerToggles ?? {}) }
    };
  });
  return getSettings(db);
}

/** Sets a per-repo failover policy (e.g. "always allow local model for this repo"). */
export function setRepoFailoverPolicy(db: JsonDatabase, projectId: string, policy: RepoFailoverPolicy): RiskRadarSettings {
  const current = db.read().settings?.repoPolicies ?? {};
  return updateSettings(db, { repoPolicies: { ...current, [projectId]: { ...(current[projectId] ?? {}), ...policy } } });
}

/** Clears all per-repo failover consent policies. */
export function resetRepoFailoverPolicies(db: JsonDatabase): RiskRadarSettings {
  db.update((state) => {
    if (state.settings) state.settings.repoPolicies = {};
  });
  return getSettings(db);
}

export function isWithinQuietHours(quietHours: string | undefined, at = new Date()): boolean {
  if (!quietHours) return false;
  const match = quietHours.match(/^(\d{2}):(\d{2})-(\d{2}):(\d{2})$/);
  if (!match) return false;
  const [, sh, sm, eh, em] = match;
  const start = Number(sh) * 60 + Number(sm);
  const end = Number(eh) * 60 + Number(em);
  const minutes = at.getHours() * 60 + at.getMinutes();
  // Overnight window (e.g. 23:00-07:00) wraps past midnight.
  return start <= end ? minutes >= start && minutes < end : minutes >= start || minutes < end;
}
