import { detectScannerTools, scannerCoverage } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Honest external-tool detection — never runs a scan. Shows install hints for
// missing tools so the operator knows exactly what to install.
const tools = detectScannerTools();
console.log(safeJson({
  ok: true,
  tools: tools.map((tool) => ({ id: tool.id, category: tool.category, status: tool.status, command: tool.command, version: tool.version, installHint: tool.status === "tool_missing" ? tool.installHint : undefined })),
  coverage: scannerCoverage().map((entry) => ({ category: entry.category, scanner: entry.scanner, status: entry.status, confidence: entry.confidence }))
}));
