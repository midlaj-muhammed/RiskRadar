import path from "node:path";
import { detectScannerTools, scannerCoverage } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Prints the honest scanner coverage matrix for the bundled fixture: which
// scanner runs per category, its status, and confidence. Green only where a real
// check can run; tool_missing/not_configured/not_applicable shown plainly.
const fixture = path.join(process.cwd(), "tests", "fixtures", "vulnerable-npm-project");
const tools = detectScannerTools();
console.log(safeJson({
  ok: true,
  externalTools: tools.map((tool) => ({ id: tool.id, status: tool.status })),
  coverage: scannerCoverage(fixture).map((entry) => ({
    category: entry.category,
    label: entry.label,
    scanner: entry.scanner,
    status: entry.status,
    confidence: entry.confidence,
    message: entry.message,
    installHint: entry.installHint
  }))
}));
