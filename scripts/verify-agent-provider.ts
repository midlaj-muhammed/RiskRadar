import { agentProviderReadiness, resolveAgentProvider } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Read-only diagnostic: which BYO provider is selected and which are ready.
// Returns env var NAMES only — never secret values.
try {
  const selectedProvider = resolveAgentProvider();
  const providers = agentProviderReadiness();
  console.log(safeJson({
    ok: true,
    selectedProvider,
    providers,
    note: "LLM providers return strict JSON plans only; RiskRadar applies safe dependency changes itself."
  }));
} catch (error) {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
}
