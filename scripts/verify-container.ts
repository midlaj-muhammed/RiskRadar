import { scanContainerImage } from "../packages/core/src/index.ts";
import { loadDotenvFile, optionalEnv, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Container image scan via Trivy. Opt-in only: requires RISKRADAR_CONTAINER_IMAGE
// (RiskRadar never pulls/scans images by default). Skips honestly when unset.
const image = process.argv[2] ?? optionalEnv("RISKRADAR_CONTAINER_IMAGE");
if (!image) {
  console.log(safeJson({ ok: true, status: "not_configured", message: "Set RISKRADAR_CONTAINER_IMAGE (or pass an image arg) to scan a container image. Skipped honestly." }));
  process.exit(0);
}

const result = scanContainerImage(image);
const ok = result.status === "completed" || result.status === "tool_missing" || result.status === "disabled";
console.log(safeJson({
  ok,
  image,
  scanner: result.scanner,
  status: result.status,
  findings: result.findings.length,
  critical: result.findings.filter((f) => f.severity === "critical").length,
  high: result.findings.filter((f) => f.severity === "high").length,
  installHint: result.installHint
}));
process.exit(ok ? 0 : 1);
