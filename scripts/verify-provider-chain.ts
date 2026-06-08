import { checkChainReadiness, clearReadinessCache, getSettings } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Reports the configured provider chain and live readiness (no secret values).
// Unconfigured providers are reported instantly with no network call.
async function main() {
  const settings = getSettings();
  clearReadinessCache();
  const started = Date.now();
  const readiness = await checkChainReadiness(settings.failover.chain, settings.failover, { forceRefresh: true });
  console.log(safeJson({
    ok: true,
    mode: settings.failover.mode,
    chain: settings.failover.chain,
    allowCloudFailover: settings.failover.allowCloudFailover,
    allowLocalFailover: settings.failover.allowLocalFailover,
    requireConsentForLowerTrust: settings.failover.requireConsentForLowerTrust,
    readinessCheckMs: Date.now() - started,
    providers: readiness.map((entry) => ({ provider: entry.provider, model: entry.model, status: entry.status, trust: entry.trust, latencyMs: entry.latencyMs, cold: entry.cold, failureReason: entry.failureReason }))
  }));
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
