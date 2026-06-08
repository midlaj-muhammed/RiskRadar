import { NextResponse } from "next/server";
import { JsonDatabase, agentProviderReadiness, detectScannerTools, integrationHealth, listAgentAdapters, scannerCoverage, watchStatus } from "@riskradar/core";

export function GET() {
  const services = Object.fromEntries(integrationHealth().map((item) => [item.name, item.status]));
  const missingIntegrations = Object.entries(services)
    .filter(([, status]) => status !== "configured" && status !== "available")
    .map(([name, status]) => ({ name, status }));
  // agentProviderReadiness exposes env var NAMES only — never secret values.
  const agentProviders = agentProviderReadiness();
  const tools = detectScannerTools();
  return NextResponse.json({
    ok: true,
    productionReady: false,
    queueMode: "inline",
    version: "0.1.0",
    agents: listAgentAdapters(),
    agentProviders,
    selectedAgentProvider: agentProviders.find((provider) => provider.selected)?.id ?? "codex",
    scannerCoverage: scannerCoverage().map((entry) => ({ category: entry.category, scanner: entry.scanner, status: entry.status })),
    scannerTools: tools.map((tool) => ({ id: tool.id, status: tool.status })),
    watch: watchStatus(new JsonDatabase()),
    services,
    missingIntegrations
  });
}
