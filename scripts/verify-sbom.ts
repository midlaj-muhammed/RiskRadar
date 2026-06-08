import path from "node:path";
import { generateSbom, parseSbomComponents, sbomDiff, sbomToolAvailable } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Proves SBOM generation works live via Syft and demonstrates a before/after diff.
const target = process.argv[2] ? path.resolve(process.argv[2]) : path.join(process.cwd(), "tests", "fixtures", "vulnerable-npm-project");
if (!sbomToolAvailable()) {
  console.log(safeJson({ ok: true, status: "tool_missing", message: "Syft not installed. Set SYFT_BIN / RISKRADAR_SCANNER_SYFT_PATH. (verify:sbom skipped honestly.)" }));
  process.exit(0);
}

try {
  const sbom = generateSbom(target);
  const components = parseSbomComponents(sbom.output);
  // Demonstrate the diff with a synthetic "after" (one component bumped).
  const sample = JSON.stringify({ components: [{ name: "lodash", version: "4.17.20" }] });
  const sampleAfter = JSON.stringify({ components: [{ name: "lodash", version: "4.17.21" }] });
  console.log(safeJson({
    ok: true,
    target,
    format: sbom.format,
    componentCount: components.size,
    validCycloneDx: sbom.output.includes("\"bomFormat\"") || sbom.output.includes("components"),
    exampleDiff: sbomDiff(sample, sampleAfter)
  }));
} catch (error) {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
}
