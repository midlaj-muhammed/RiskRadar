import { verifyDeploymentUrl } from "../packages/core/src/index.ts";
import { loadDotenvFile, optionalEnv, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Verifies a deployment/preview URL is live (no deploy triggered). Opt-in: pass a
// URL arg or set RISKRADAR_DEPLOYMENT_URL. Skips honestly when unset.
async function main() {
  const url = process.argv[2] ?? optionalEnv("RISKRADAR_DEPLOYMENT_URL");
  if (!url) {
    console.log(safeJson({ ok: true, status: "not_configured", message: "Pass a URL arg or set RISKRADAR_DEPLOYMENT_URL to verify a deployment. Skipped honestly." }));
    process.exit(0);
  }
  const check = await verifyDeploymentUrl(url);
  console.log(safeJson({ ok: check.ok, check }));
  process.exit(check.ok ? 0 : 1);
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
