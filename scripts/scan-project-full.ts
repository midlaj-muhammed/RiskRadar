import { existsSync } from "node:fs";
import path from "node:path";
import { runProjectScanners, scannerCoverage } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// pnpm scan:project-full [path] — runs all applicable scanners against a path
// (defaults to the bundled vulnerable fixture). Built-ins always run; external
// scanners run only when installed (else honest tool_missing). No raw secrets.
const target = process.argv[2] ? path.resolve(process.argv[2]) : path.join(process.cwd(), "tests", "fixtures", "vulnerable-npm-project");
if (!existsSync(target)) {
  console.error(safeJson({ ok: false, error: `Path not found: ${target}` }));
  process.exit(2);
}

const results = runProjectScanners(target, undefined, {});
const byCategory: Record<string, { scanner: string; status: string; findings: number; critical: number; high: number; errors: string[]; durationMs?: number }> = {};
for (const result of results) {
  byCategory[result.scanner] = {
    scanner: result.scanner,
    status: result.status,
    findings: result.findings.length,
    critical: result.findings.filter((f) => f.severity === "critical").length,
    high: result.findings.filter((f) => f.severity === "high").length,
    errors: result.errors,
    durationMs: result.durationMs
  };
}
console.log(safeJson({
  ok: true,
  target,
  coverage: scannerCoverage(target).map((entry) => ({ category: entry.category, scanner: entry.scanner, status: entry.status })),
  scanners: byCategory,
  // Findings are redacted (secret evidence is masked at the source).
  sampleFindings: results.flatMap((r) => r.findings).slice(0, 20).map((f) => ({ scanner: f.scanner, category: f.category, severity: f.severity, title: f.title, evidencePath: f.evidencePath, redactedEvidence: f.redactedEvidence, confidence: f.confidence }))
}));
