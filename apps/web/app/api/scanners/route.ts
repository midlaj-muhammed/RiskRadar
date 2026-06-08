import { NextResponse } from "next/server";
import { detectScannerTools, scannerCoverage } from "@riskradar/core";

// Honest scanner coverage + external tool detection. No secrets, no fake green.
export function GET() {
  return NextResponse.json({ ok: true, tools: detectScannerTools(), coverage: scannerCoverage() });
}
