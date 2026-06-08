import { existsSync, readFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";

type McpConfig = {
  mcpServers?: Record<string, { command?: string; args?: string[] }>;
};

const pluginDir = process.env.RISKRADAR_CODEX_PLUGIN_DIR ?? path.join(os.homedir(), "plugins", "riskradar");
const mcpConfigPath = path.join(pluginDir, ".mcp.json");

if (!existsSync(mcpConfigPath)) {
  console.log(JSON.stringify({ ok: false, status: "plugin_missing", pluginDir, mcpConfigPath }, null, 2));
  process.exit(1);
}

const config = JSON.parse(readFileSync(mcpConfigPath, "utf8")) as McpConfig;
const server = config.mcpServers?.riskradar;
if (!server?.command) {
  console.log(JSON.stringify({ ok: false, status: "mcp_server_missing", pluginDir, mcpConfigPath }, null, 2));
  process.exit(1);
}

const transport = new StdioClientTransport({
  command: server.command,
  args: server.args ?? []
});
const client = new Client({ name: "riskradar-codex-plugin-verifier", version: "0.1.0" });

await client.connect(transport);
try {
  const tools = await client.listTools();
  const names = tools.tools.map((tool) => tool.name).sort();
  const scannerCoverage = await client.callTool({
    name: "riskradar.get_scanner_coverage",
    arguments: {}
  });
  const scannerContent = Array.isArray(scannerCoverage.content) ? scannerCoverage.content : [];
  const scannerCoverageBytes = scannerContent[0]?.type === "text" && typeof scannerContent[0].text === "string"
    ? scannerContent[0].text.length
    : 0;
  const required = [
    "riskradar.get_provider_readiness",
    "riskradar.get_scanner_coverage",
    "riskradar.get_watch_status",
    "riskradar.get_approval_queue",
    "riskradar.request_remediation"
  ];
  const missingRequired = required.filter((name) => !names.includes(name));
  const ok = names.length >= 20 && missingRequired.length === 0 && scannerCoverageBytes > 0;
  console.log(JSON.stringify({
    ok,
    status: ok ? "verified" : "incomplete",
    pluginDir,
    toolCount: names.length,
    tools: names,
    missingRequired,
    scannerCoverageBytes
  }, null, 2));
  if (!ok) process.exitCode = 1;
} finally {
  await client.close();
}
