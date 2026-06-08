import { NextResponse } from "next/server";
import { JsonDatabase, agentProviderReadiness, getSettings } from "@riskradar/core";

const PROVIDER_ACTIONS = new Set([
  "provider_chain_started", "provider_readiness_checked", "provider_attempt_started",
  "provider_attempt_failed", "provider_attempt_completed", "provider_failover_consent_requested",
  "provider_failover_consent_approved", "provider_failover_consent_rejected",
  "local_model_used", "deterministic_fallback_used"
]);

// Provider readiness + chain settings + recent failover timeline + pending
// consents. agentProviderReadiness exposes env NAMES only — never secret values.
export function GET() {
  const db = new JsonDatabase();
  const state = db.read();
  const timeline = state.auditReceipts
    .filter((receipt) => PROVIDER_ACTIONS.has(receipt.action))
    .slice(-25).reverse()
    .map((receipt) => ({ action: receipt.action, at: receipt.createdAt, agent: receipt.agent, summary: receipt.outputSummary }));
  const consents = (state.providerConsents ?? []).slice(-15).reverse()
    .map((consent) => ({ id: consent.id, status: consent.status, candidateProvider: consent.candidateProvider, candidateTrust: consent.candidateTrust, failedProvider: consent.failedProvider, createdAt: consent.createdAt }));
  return NextResponse.json({
    ok: true,
    settings: getSettings(db).failover,
    providers: agentProviderReadiness(),
    pendingConsents: consents.filter((consent) => consent.status === "pending"),
    consents,
    timeline
  });
}
