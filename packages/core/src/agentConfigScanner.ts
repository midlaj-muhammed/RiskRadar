import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { id, now } from "./database";
import { redact } from "./redaction";
import type { AgentConfigFinding } from "./types";

const CONFIG_NAMES = new Set(["mcp.json", "package.json"]);
const SECRET_FILE_PATTERNS = [/^\.env($|\.)/, /id_rsa/i, /\.pem$/i, /\.key$/i];

export function scanAgentConfig(projectPath: string, projectId?: string): AgentConfigFinding[] {
  const findings: AgentConfigFinding[] = [];
  walk(projectPath, (filePath) => {
    const rel = path.relative(projectPath, filePath);
    const base = path.basename(filePath);
    if (SECRET_FILE_PATTERNS.some((pattern) => pattern.test(base))) {
      findings.push(makeFinding(projectId, rel, undefined, "Secret-like file is present in the project tree.", "critical", "Remove secrets from the repository and rotate exposed credentials."));
      return;
    }
    if (rel.endsWith(path.join(".codex", "config.toml"))) {
      const content = readFileSync(filePath, "utf8");
      addPatternFindings(findings, projectId, rel, content, [
        ["dangerously-bypass-approvals-and-sandbox", "critical", "Codex approval and sandbox bypass is enabled.", "Remove bypass mode and use workspace-write sandboxing."],
        ["danger-full-access", "critical", "Codex sandbox has full filesystem access.", "Use workspace-write or read-only sandboxing for remediation workers."]
      ]);
    }
    if (rel.includes(".github" + path.sep + "workflows") && rel.endsWith(".yml")) {
      const content = readFileSync(filePath, "utf8");
      addPatternFindings(findings, projectId, rel, content, [
        ["permissions: write-all", "high", "GitHub Actions grants broad write permissions.", "Scope workflow permissions to the minimum required."],
        ["pull_request_target", "medium", "pull_request_target can be risky with untrusted checkout patterns.", "Avoid checking out untrusted code with write tokens."]
      ]);
      if (/uses:\s*[^@\s]+\/[^@\s]+\s*$/m.test(content)) {
        findings.push(makeFinding(projectId, rel, undefined, "Unpinned third-party GitHub Action detected.", "medium", "Pin third-party actions to a full commit SHA."));
      }
    }
    const isMcp = base === "mcp.json" || rel.endsWith(path.join(".cursor", "mcp.json")) || rel.endsWith(path.join(".vscode", "mcp.json"));
    if (CONFIG_NAMES.has(base) || isMcp) {
      const content = readFileSync(filePath, "utf8");
      addPatternFindings(findings, projectId, rel, content, [
        ["curl ", "high", "Config references curl; possible remote code execution path.", "Review and pin downloaded artifacts; avoid curl-pipe-shell patterns."],
        ["powershell", "high", "MCP/tool config invokes PowerShell.", "Allow only reviewed commands in MCP/tool configs."],
        ["postinstall", "medium", "package.json includes postinstall lifecycle script.", "Review lifecycle scripts before validation installs."],
        ["preinstall", "medium", "package.json includes preinstall lifecycle script.", "Review lifecycle scripts before validation installs."]
      ]);
    }
    if (isMcp) {
      const content = readFileSync(filePath, "utf8");
      // MCP-specific supply-chain risks (the 2026 agent attack surface).
      addPatternFindings(findings, projectId, rel, content, [
        ["autoApprove", "high", "MCP server runs with autoApprove enabled; tools execute without human review (tool-poisoning risk).", "Disable autoApprove, or scope it to specific read-only tools."],
        ["\"yolo\"", "high", "MCP/agent config uses a 'yolo'/no-confirm mode.", "Require confirmation for tool calls."],
        ["\"sh\"", "medium", "MCP server launches a shell; review the tool's command surface.", "Avoid shell tools, or constrain allowed commands."],
        ["\"bash\"", "medium", "MCP server launches a shell; review the tool's command surface.", "Avoid shell tools, or constrain allowed commands."]
      ]);
      // Hardcoded credential embedded in an agent config.
      const lines = content.split(/\r?\n/);
      const credRe = /(ghp_[A-Za-z0-9]{8,}|gho_[A-Za-z0-9]{8,}|sk-[A-Za-z0-9]{10,}|AKIA[A-Z0-9]{12,}|xox[baprs]-[A-Za-z0-9-]{8,}|glpat-[A-Za-z0-9_-]{8,})/;
      const credLine = lines.findIndex((line) => credRe.test(line));
      if (credLine >= 0) {
        findings.push(makeFinding(projectId, rel, credLine + 1, "Hardcoded credential embedded in an MCP/agent config.", "high", "Move secrets to a secret manager or environment injection; never commit tokens in agent configs.", redact(lines[credLine] ?? "")));
      }
    }
  });
  return findings;
}

function walk(root: string, visit: (filePath: string) => void) {
  if (!existsSync(root)) return;
  for (const entry of readdirSync(root)) {
    if (["node_modules", ".git", ".next", "dist", "build"].includes(entry)) continue;
    const full = path.join(root, entry);
    const stat = statSync(full);
    if (stat.isDirectory()) walk(full, visit);
    else if (stat.isFile()) visit(full);
  }
}

function addPatternFindings(
  findings: AgentConfigFinding[],
  projectId: string | undefined,
  rel: string,
  content: string,
  checks: Array<[string, AgentConfigFinding["severity"], string, string]>
) {
  const lines = content.split(/\r?\n/);
  for (const [needle, severity, reason, recommendation] of checks) {
    const lineIndex = lines.findIndex((line) => line.includes(needle));
    if (lineIndex >= 0) {
      findings.push(makeFinding(projectId, rel, lineIndex + 1, reason, severity, recommendation, redact(lines[lineIndex] ?? "")));
    }
  }
}

function makeFinding(
  projectId: string | undefined,
  filePath: string,
  line: number | undefined,
  reason: string,
  severity: AgentConfigFinding["severity"],
  recommendation: string,
  redactedSnippet?: string
): AgentConfigFinding {
  return { id: id("agent"), projectId, filePath, line, reason, severity, recommendation, redactedSnippet, createdAt: now() };
}
