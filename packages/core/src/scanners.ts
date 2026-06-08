import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { id, now } from "./database";
import { commandExists, getEnv } from "./env";
import { redact } from "./redaction";
import { scanAgentConfig } from "./agentConfigScanner";

export type ScannerStatus =
  | "enabled"
  | "disabled"
  | "tool_missing"
  | "not_configured"
  | "not_applicable"
  | "running"
  | "completed"
  | "error";

export type ScannerCategory =
  | "sca"
  | "secret"
  | "sast"
  | "iac"
  | "container"
  | "ci"
  | "agent"
  | "malware"
  | "license"
  | "sbom";

export type ScannerSeverity = "critical" | "high" | "medium" | "low" | "info" | "unknown";

export interface ScannerFinding {
  id: string;
  scanner: string;
  category: ScannerCategory;
  severity: ScannerSeverity;
  title: string;
  description: string;
  evidencePath?: string;
  evidenceLine?: number;
  redactedEvidence?: string;
  packageName?: string;
  installedVersion?: string;
  fixedVersion?: string;
  advisoryIds?: string[];
  cveIds?: string[];
  source: string;
  confidence: "high" | "medium" | "low";
  remediation?: string;
}

export interface ScannerResult {
  scanner: string;
  category: ScannerCategory;
  status: ScannerStatus;
  version?: string;
  startedAt?: string;
  finishedAt?: string;
  durationMs?: number;
  findings: ScannerFinding[];
  errors: string[];
  installHint?: string;
  /** False when the scan ran but could not cover everything (e.g. no lockfile). */
  complete: boolean;
}

interface ExternalTool {
  id: string;
  category: ScannerCategory;
  label: string;
  pathEnv: string;
  enabledEnv: string;
  defaultCommand: string;
  defaultEnabled: boolean;
  installHint: string;
}

export const EXTERNAL_SCANNER_TOOLS: ExternalTool[] = [
  { id: "osv-scanner", category: "sca", label: "OSV-Scanner (lockfile SCA)", pathEnv: "RISKRADAR_SCANNER_OSV_SCANNER_PATH", enabledEnv: "RISKRADAR_SCANNER_OSV_ENABLED", defaultCommand: "osv-scanner", defaultEnabled: true, installHint: "Install OSV-Scanner: https://google.github.io/osv-scanner/installation/" },
  { id: "gitleaks", category: "secret", label: "Gitleaks (secret scanner)", pathEnv: "RISKRADAR_SCANNER_GITLEAKS_PATH", enabledEnv: "RISKRADAR_SCANNER_GITLEAKS_ENABLED", defaultCommand: "gitleaks", defaultEnabled: true, installHint: "Install Gitleaks: https://github.com/gitleaks/gitleaks#installing" },
  { id: "semgrep", category: "sast", label: "Semgrep (SAST)", pathEnv: "RISKRADAR_SCANNER_SEMGREP_PATH", enabledEnv: "RISKRADAR_SCANNER_SEMGREP_ENABLED", defaultCommand: "semgrep", defaultEnabled: true, installHint: "Install Semgrep: https://semgrep.dev/docs/getting-started/" },
  { id: "trivy", category: "container", label: "Trivy (fs/IaC/license/SBOM)", pathEnv: "RISKRADAR_SCANNER_TRIVY_PATH", enabledEnv: "RISKRADAR_SCANNER_TRIVY_ENABLED", defaultCommand: "trivy", defaultEnabled: true, installHint: "Install Trivy: https://aquasecurity.github.io/trivy/latest/getting-started/installation/" },
  { id: "syft", category: "sbom", label: "Syft (SBOM)", pathEnv: "RISKRADAR_SCANNER_SYFT_PATH", enabledEnv: "RISKRADAR_SCANNER_SYFT_ENABLED", defaultCommand: "syft", defaultEnabled: false, installHint: "Install Syft: https://github.com/anchore/syft#installation" }
];

export interface ScannerToolInfo {
  id: string;
  category: ScannerCategory;
  label: string;
  status: "enabled" | "disabled" | "tool_missing";
  command: string;
  version?: string;
  installHint: string;
}

function toolEnabled(tool: ExternalTool): boolean {
  const value = getEnv(tool.enabledEnv);
  if (value === undefined) return tool.defaultEnabled;
  return value.toLowerCase() === "true";
}

function toolCommand(tool: ExternalTool): string {
  return getEnv(tool.pathEnv) ?? tool.defaultCommand;
}

function scannerTimeoutMs(): number {
  const value = Number(getEnv("RISKRADAR_SCANNER_TIMEOUT_MS"));
  return Number.isFinite(value) && value > 0 ? value : 120000;
}

// Robust Windows-safe tool spawn:
// - .cmd/.bat → run through cmd.exe (argv-quoted, handles spaces)
// - absolute .exe / path → spawn directly, no shell (handles spaces)
// - bare name → shell (PATH/PATHEXT resolution)
function spawnTool(command: string, args: string[], options: { cwd?: string; timeoutMs?: number; maxBuffer?: number }) {
  const base = { encoding: "utf8" as const, cwd: options.cwd, timeout: options.timeoutMs, maxBuffer: options.maxBuffer };
  if (process.platform === "win32" && /\.(cmd|bat)$/i.test(command)) {
    return spawnSync(process.env.ComSpec ?? "cmd.exe", ["/d", "/c", command, ...args], base);
  }
  const bare = !command.includes("\\") && !command.includes("/");
  return spawnSync(command, args, { ...base, shell: bare && process.platform === "win32" });
}

function probeVersion(command: string): string | undefined {
  if (command === WSL_SEMGREP) return semgrepWslVersion();
  const result = spawnTool(command, ["--version"], { timeoutMs: 5000 });
  if ((result.status ?? 1) !== 0) return undefined;
  return redact((result.stdout || result.stderr || "").split(/\r?\n/)[0]?.trim() ?? "").slice(0, 80) || undefined;
}

// ---- WSL-backed Semgrep (Windows) ----
// Semgrep's launcher doesn't run on native Windows, but it works under WSL.
// When WSL has semgrep, RiskRadar runs it there transparently.
const WSL_SEMGREP = "wsl:semgrep";
// Resolve semgrep inside WSL whether or not ~/.local/bin is on PATH.
const WSL_SEMGREP_BIN = '"$(command -v semgrep || echo "$HOME/.local/bin/semgrep")"';

/** Translates a Windows path (C:\\a\\b) to a WSL path (/mnt/c/a/b). */
function toWslPath(p: string): string {
  const m = /^([A-Za-z]):[\\/](.*)$/.exec(p);
  return m ? `/mnt/${m[1]!.toLowerCase()}/${m[2]!.replace(/\\/g, "/")}` : p;
}

/** Returns the WSL semgrep version (with a "(WSL)" tag) when available on Windows. */
function semgrepWslVersion(): string | undefined {
  if (process.platform !== "win32") return undefined;
  const r = spawnSync("wsl", ["bash", "-lc", `${WSL_SEMGREP_BIN} --version`], { encoding: "utf8", timeout: 12000 });
  if ((r.status ?? 1) !== 0) return undefined;
  const v = (r.stdout || "").trim().split(/\r?\n/).pop()?.trim();
  return v && /^\d+\.\d+/.test(v) ? `${v} (WSL)` : undefined;
}

/** Honest external-tool detection — never runs a scan, only checks availability. */
export function detectScannerTools(): ScannerToolInfo[] {
  return EXTERNAL_SCANNER_TOOLS.map((tool) => {
    // Windows: Semgrep can't run natively but works under WSL. If the native
    // command is missing and WSL has semgrep, report it as enabled via WSL.
    if (tool.id === "semgrep" && toolEnabled(tool) && process.platform === "win32" && !commandExists(toolCommand(tool))) {
      const wslVersion = semgrepWslVersion();
      if (wslVersion) {
        return { id: tool.id, category: tool.category, label: tool.label, status: "enabled" as const, command: WSL_SEMGREP, version: wslVersion, installHint: tool.installHint };
      }
    }
    return detectOne(tool);
  });
}

function detectOne(tool: (typeof EXTERNAL_SCANNER_TOOLS)[number]): ScannerToolInfo {
  const command = toolCommand(tool);
  if (!toolEnabled(tool)) {
    return { id: tool.id, category: tool.category, label: tool.label, status: "disabled", command, installHint: tool.installHint };
  }
  if (!commandExists(command)) {
    return { id: tool.id, category: tool.category, label: tool.label, status: "tool_missing", command, installHint: tool.installHint };
  }
  const version = probeVersion(command);
  if (!version) {
    return { id: tool.id, category: tool.category, label: tool.label, status: "tool_missing", command, installHint: `${tool.installHint} The configured command exists but did not return a usable --version response.` };
  }
  return { id: tool.id, category: tool.category, label: tool.label, status: "enabled", command, version, installHint: tool.installHint };
}

// ---------- pure helpers ----------

function makeFinding(input: Omit<ScannerFinding, "id">): ScannerFinding {
  return { id: id("scanf"), ...input };
}

function walkFiles(root: string, visit: (filePath: string) => void, depth = 0): void {
  if (depth > 12 || !existsSync(root)) return;
  for (const entry of readdirSync(root)) {
    if (["node_modules", ".git", ".next", "dist", "build", ".turbo", "vendor", ".venv"].includes(entry)) continue;
    const full = path.join(root, entry);
    let stat;
    try {
      stat = statSync(full);
    } catch {
      continue;
    }
    if (stat.isDirectory()) walkFiles(full, visit, depth + 1);
    else if (stat.isFile()) visit(full);
  }
}

function maskSecret(value: string): string {
  const trimmed = value.trim();
  if (trimmed.length <= 8) return "***";
  return `${trimmed.slice(0, 3)}***${trimmed.slice(-2)}`;
}

// ---------- built-in scanners (no external tool) ----------

const SECRET_RULES: Array<{ type: string; pattern: RegExp }> = [
  { type: "aws_access_key", pattern: /AKIA[0-9A-Z]{16}/ },
  { type: "github_token", pattern: /gh[pousr]_[A-Za-z0-9_]{20,}/ },
  { type: "github_pat", pattern: /github_pat_[A-Za-z0-9_]{40,}/ },
  { type: "openai_key", pattern: /sk-[A-Za-z0-9_-]{20,}/ },
  { type: "slack_token", pattern: /xox[baprs]-[A-Za-z0-9-]{10,}/ },
  { type: "telegram_bot_token", pattern: /\b\d{8,10}:[A-Za-z0-9_-]{30,}\b/ },
  { type: "private_key", pattern: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  { type: "generic_assignment", pattern: /(?:password|secret|api[_-]?key|access[_-]?token)\s*[:=]\s*["']?[^\s"']{12,}/i }
];

const SECRET_SCANNABLE = /\.(env|ya?ml|json|js|ts|tsx|py|go|rb|sh|cfg|ini|toml|properties|txt)$/i;

/**
 * Lightweight, low-confidence built-in secret detector. Stores only a masked
 * preview — never the raw secret. Clearly NOT a substitute for Gitleaks.
 */
export function scanSecretsLightweight(projectPath: string): ScannerFinding[] {
  const findings: ScannerFinding[] = [];
  walkFiles(projectPath, (filePath) => {
    const base = path.basename(filePath);
    if (!SECRET_SCANNABLE.test(base)) return;
    let content = "";
    try {
      content = readFileSync(filePath, "utf8");
    } catch {
      return;
    }
    if (content.length > 2_000_000) return;
    const lines = content.split(/\r?\n/);
    lines.forEach((line, index) => {
      for (const rule of SECRET_RULES) {
        const match = line.match(rule.pattern);
        if (match) {
          findings.push(makeFinding({
            scanner: "riskradar-secrets-lite",
            category: "secret",
            severity: "high",
            title: `Possible ${rule.type} in ${path.relative(projectPath, filePath)}`,
            description: "Lightweight built-in detector flagged a possible secret. This is low-confidence; install Gitleaks for authoritative secret scanning.",
            evidencePath: path.relative(projectPath, filePath),
            evidenceLine: index + 1,
            redactedEvidence: maskSecret(match[0]),
            source: "riskradar-secrets-lite (lightweight)",
            confidence: "low",
            remediation: "Rotate the credential and remove it from the repository; load secrets from environment/secret manager."
          }));
          break;
        }
      }
    });
  });
  return findings;
}

const CI_RULES: Array<{ needle: RegExp; severity: ScannerSeverity; title: string; remediation: string }> = [
  { needle: /permissions:\s*write-all/, severity: "high", title: "GitHub Actions grants write-all permissions", remediation: "Scope workflow permissions to the minimum required." },
  { needle: /pull_request_target/, severity: "medium", title: "pull_request_target can run untrusted code with write tokens", remediation: "Avoid checking out untrusted head_ref with a privileged token." },
  { needle: /curl\s+[^|\n]*\|\s*(?:ba)?sh/, severity: "high", title: "curl | bash pattern in workflow", remediation: "Pin and verify downloaded artifacts; avoid curl-pipe-shell." },
  { needle: /workflow_dispatch/, severity: "low", title: "workflow_dispatch present (review dangerous inputs)", remediation: "Validate and constrain manual dispatch inputs." }
];

/** Built-in static CI hardening scanner for GitHub Actions workflows. */
export function scanCiHardening(projectPath: string): ScannerFinding[] {
  const workflowsDir = path.join(projectPath, ".github", "workflows");
  if (!existsSync(workflowsDir)) return [];
  const findings: ScannerFinding[] = [];
  for (const entry of readdirSync(workflowsDir)) {
    if (!/\.ya?ml$/i.test(entry)) continue;
    const filePath = path.join(workflowsDir, entry);
    const rel = path.relative(projectPath, filePath);
    let content = "";
    try {
      content = readFileSync(filePath, "utf8");
    } catch {
      continue;
    }
    const lines = content.split(/\r?\n/);
    for (const rule of CI_RULES) {
      const index = lines.findIndex((line) => rule.needle.test(line));
      if (index >= 0) {
        findings.push(makeFinding({
          scanner: "riskradar-ci-hardening",
          category: "ci",
          severity: rule.severity,
          title: rule.title,
          description: `${rule.title} in ${rel}.`,
          evidencePath: rel,
          evidenceLine: index + 1,
          redactedEvidence: redact(lines[index] ?? "").trim().slice(0, 200),
          source: "riskradar-ci-hardening",
          confidence: "medium",
          remediation: rule.remediation
        }));
      }
    }
    // Unpinned third-party action (uses: owner/repo without @sha).
    lines.forEach((line, index) => {
      const uses = line.match(/uses:\s*([^@\s]+\/[^@\s]+)(@([^\s]+))?/);
      if (uses && uses[1] && !uses[1].startsWith(".")) {
        const ref = uses[3];
        if (!ref || !/^[0-9a-f]{40}$/i.test(ref)) {
          findings.push(makeFinding({
            scanner: "riskradar-ci-hardening",
            category: "ci",
            severity: "medium",
            title: `Unpinned action ${uses[1]}`,
            description: `Third-party action ${uses[1]} is not pinned to a full commit SHA in ${rel}.`,
            evidencePath: rel,
            evidenceLine: index + 1,
            redactedEvidence: line.trim().slice(0, 200),
            source: "riskradar-ci-hardening",
            confidence: "medium",
            remediation: "Pin third-party actions to a full 40-character commit SHA."
          }));
        }
      }
    });
  }
  return findings;
}

const POPULAR_PACKAGES = [
  "lodash", "react", "react-dom", "express", "axios", "chalk", "commander", "debug",
  "moment", "request", "webpack", "next", "vue", "typescript", "eslint", "jest",
  "dotenv", "uuid", "classnames", "redux", "tslib", "yargs", "rimraf", "glob"
];

// Optimal string alignment (Damerau-Levenshtein) distance — counts an adjacent
// transposition (e.g. lodahs↔lodash) as one edit, which typosquats often are.
function editDistance(a: string, b: string): number {
  const matrix = Array.from({ length: a.length + 1 }, () => Array(b.length + 1).fill(0));
  for (let i = 0; i <= a.length; i += 1) matrix[i]![0] = i;
  for (let j = 0; j <= b.length; j += 1) matrix[0]![j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[i]![j] = Math.min(matrix[i - 1]![j]! + 1, matrix[i]![j - 1]! + 1, matrix[i - 1]![j - 1]! + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        matrix[i]![j] = Math.min(matrix[i]![j]!, matrix[i - 2]![j - 2]! + 1);
      }
    }
  }
  return matrix[a.length]![b.length]!;
}

/** Returns the popular package a name appears to typosquat, or undefined. */
export function typosquatTarget(name: string): string | undefined {
  const lower = name.toLowerCase();
  if (lower.length < 4 || POPULAR_PACKAGES.includes(lower)) return undefined;
  return POPULAR_PACKAGES.find((popular) => Math.abs(popular.length - lower.length) <= 1 && editDistance(lower, popular) === 1);
}

/**
 * Package quarantine / suspicious-package heuristics. Labels findings
 * "malicious" ONLY when matched against a configured OpenSSF data directory;
 * otherwise "suspicious"/"needs_review".
 */
export function scanMaliciousPackages(projectPath: string, options: { maliciousDir?: string } = {}): ScannerFinding[] {
  const manifestPath = path.join(projectPath, "package.json");
  if (!existsSync(manifestPath)) return [];
  let manifest: { dependencies?: Record<string, string>; devDependencies?: Record<string, string>; scripts?: Record<string, string> };
  try {
    manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  } catch {
    return [];
  }
  const findings: ScannerFinding[] = [];
  const maliciousDir = options.maliciousDir ?? getEnv("RISKRADAR_MALICIOUS_PACKAGES_DIR");
  const allDeps = { ...(manifest.dependencies ?? {}), ...(manifest.devDependencies ?? {}) };
  for (const [name] of Object.entries(allDeps)) {
    if (maliciousDir && existsSync(path.join(maliciousDir, `${name}.json`))) {
      findings.push(makeFinding({
        scanner: "riskradar-quarantine",
        category: "malware",
        severity: "critical",
        title: `Known malicious package: ${name}`,
        description: "Package matched a configured OpenSSF malicious-package data entry.",
        packageName: name,
        source: `openssf-malicious-packages (${maliciousDir})`,
        confidence: "high",
        remediation: "Remove the package immediately and audit installs."
      }));
    }
  }
  // Low-confidence typosquat heuristic: a dependency one edit away from a very
  // popular package (and not that package) is flagged "suspicious" — never
  // "malicious" without a configured source.
  for (const name of Object.keys(allDeps)) {
    const target = typosquatTarget(name);
    if (target) {
      findings.push(makeFinding({
        scanner: "riskradar-quarantine",
        category: "malware",
        severity: "medium",
        title: `Possible typosquat: ${name} resembles ${target}`,
        description: `Dependency "${name}" is one character away from the popular package "${target}". Heuristic only — verify the package is intended.`,
        packageName: name,
        source: "riskradar-quarantine (typosquat heuristic)",
        confidence: "low",
        remediation: `Confirm "${name}" is the intended package and not a typo of "${target}".`
      }));
    }
  }
  for (const script of ["preinstall", "install", "postinstall"]) {
    if (manifest.scripts?.[script]) {
      findings.push(makeFinding({
        scanner: "riskradar-quarantine",
        category: "malware",
        severity: "medium",
        title: `Lifecycle script: ${script}`,
        description: `package.json defines a ${script} lifecycle script, which can execute code on install.`,
        evidencePath: "package.json",
        redactedEvidence: redact(String(manifest.scripts[script])).slice(0, 200),
        source: "riskradar-quarantine",
        confidence: "medium",
        remediation: "Review lifecycle scripts; install with --ignore-scripts during validation."
      }));
    }
  }
  return findings;
}

// ---------- external scanner JSON parsers (pure, testable) ----------

export function parseGitleaksJson(json: string): ScannerFinding[] {
  let data: Array<{ RuleID?: string; Description?: string; File?: string; StartLine?: number; Secret?: string; Match?: string }>;
  try {
    data = JSON.parse(json);
  } catch {
    return [];
  }
  if (!Array.isArray(data)) return [];
  return data.map((item) => makeFinding({
    scanner: "gitleaks",
    category: "secret",
    severity: "high",
    title: `${item.RuleID ?? "secret"} detected`,
    description: item.Description ?? "Gitleaks detected a secret.",
    evidencePath: item.File,
    evidenceLine: item.StartLine,
    // Never store the raw secret — mask it.
    redactedEvidence: item.Secret ? maskSecret(item.Secret) : item.Match ? maskSecret(item.Match) : undefined,
    source: "gitleaks",
    confidence: "high",
    remediation: "Rotate the exposed credential and remove it from history."
  }));
}

export function parseSemgrepJson(json: string): ScannerFinding[] {
  let data: { results?: Array<{ check_id?: string; path?: string; start?: { line?: number }; extra?: { message?: string; severity?: string; metadata?: { fix?: string } } }> };
  try {
    data = JSON.parse(json);
  } catch {
    return [];
  }
  const sevMap: Record<string, ScannerSeverity> = { ERROR: "high", WARNING: "medium", INFO: "low" };
  return (data.results ?? []).map((item) => makeFinding({
    scanner: "semgrep",
    category: "sast",
    severity: sevMap[(item.extra?.severity ?? "").toUpperCase()] ?? "unknown",
    title: item.check_id ?? "semgrep finding",
    description: redact(item.extra?.message ?? "Semgrep rule match.").slice(0, 500),
    evidencePath: item.path,
    evidenceLine: item.start?.line,
    source: "semgrep",
    confidence: "high",
    remediation: item.extra?.metadata?.fix
  }));
}

export type LicensePolicyStatus = "allowed" | "review" | "blocked" | "unknown";

/**
 * Loads a license policy file. Accepts `{ allowed:[], review:[], blocked:[] }`
 * or a flat `{ "GPL-3.0": "blocked" }` map. Returns undefined when unset/missing.
 */
export function loadLicensePolicy(policyPath = getEnv("RISKRADAR_LICENSE_POLICY_PATH")): Record<string, LicensePolicyStatus> | undefined {
  if (!policyPath || !existsSync(policyPath)) return undefined;
  try {
    const raw = JSON.parse(readFileSync(policyPath, "utf8")) as Record<string, unknown>;
    const map: Record<string, LicensePolicyStatus> = {};
    for (const status of ["allowed", "review", "blocked"] as const) {
      const list = raw[status];
      if (Array.isArray(list)) for (const license of list) if (typeof license === "string") map[license.toLowerCase()] = status;
    }
    for (const [key, value] of Object.entries(raw)) {
      if (typeof value === "string" && (value === "allowed" || value === "review" || value === "blocked")) map[key.toLowerCase()] = value;
    }
    return Object.keys(map).length > 0 ? map : undefined;
  } catch {
    return undefined;
  }
}

export function licensePolicyStatus(license: string, policy?: Record<string, LicensePolicyStatus>): LicensePolicyStatus {
  if (!policy) return "unknown";
  return policy[license.toLowerCase()] ?? "unknown";
}

export function parseTrivyJson(json: string, options: { licensePolicy?: Record<string, LicensePolicyStatus> } = {}): ScannerFinding[] {
  let data: { Results?: Array<{ Target?: string; Type?: string; Class?: string; Vulnerabilities?: Array<{ VulnerabilityID?: string; PkgName?: string; InstalledVersion?: string; FixedVersion?: string; Severity?: string; Title?: string }>; Misconfigurations?: Array<{ ID?: string; Title?: string; Severity?: string; Message?: string }>; Secrets?: Array<{ RuleID?: string; Title?: string; StartLine?: number; Match?: string }>; Licenses?: Array<{ PkgName?: string; Name?: string; Severity?: string }> }> };
  try {
    data = JSON.parse(json);
  } catch {
    return [];
  }
  const sev = (value?: string): ScannerSeverity => {
    const v = (value ?? "").toLowerCase();
    return v === "critical" || v === "high" || v === "medium" || v === "low" ? v : "unknown";
  };
  const findings: ScannerFinding[] = [];
  for (const result of data.Results ?? []) {
    for (const vuln of result.Vulnerabilities ?? []) {
      findings.push(makeFinding({
        scanner: "trivy",
        category: "container",
        severity: sev(vuln.Severity),
        title: vuln.Title ?? vuln.VulnerabilityID ?? "vulnerability",
        description: `${vuln.VulnerabilityID ?? ""} in ${vuln.PkgName ?? "package"}`.trim(),
        evidencePath: result.Target,
        packageName: vuln.PkgName,
        installedVersion: vuln.InstalledVersion,
        fixedVersion: vuln.FixedVersion,
        cveIds: vuln.VulnerabilityID?.startsWith("CVE-") ? [vuln.VulnerabilityID] : undefined,
        advisoryIds: vuln.VulnerabilityID ? [vuln.VulnerabilityID] : undefined,
        source: "trivy",
        confidence: "high"
      }));
    }
    for (const misconfig of result.Misconfigurations ?? []) {
      findings.push(makeFinding({
        scanner: "trivy",
        category: "iac",
        severity: sev(misconfig.Severity),
        title: misconfig.Title ?? misconfig.ID ?? "misconfiguration",
        description: redact(misconfig.Message ?? "").slice(0, 500),
        evidencePath: result.Target,
        source: "trivy",
        confidence: "high"
      }));
    }
    for (const secret of result.Secrets ?? []) {
      findings.push(makeFinding({
        scanner: "trivy",
        category: "secret",
        severity: "high",
        title: secret.Title ?? secret.RuleID ?? "secret",
        description: "Trivy detected a secret.",
        evidencePath: result.Target,
        evidenceLine: secret.StartLine,
        redactedEvidence: secret.Match ? maskSecret(secret.Match) : undefined,
        source: "trivy",
        confidence: "high"
      }));
    }
    for (const license of result.Licenses ?? []) {
      const name = license.Name ?? "unknown";
      const policyStatus = licensePolicyStatus(name, options.licensePolicy);
      const severity: ScannerSeverity = policyStatus === "blocked" ? "high" : policyStatus === "review" ? "medium" : policyStatus === "allowed" ? "info" : sev(license.Severity);
      findings.push(makeFinding({
        scanner: "trivy",
        category: "license",
        severity,
        title: `License ${name} (${license.PkgName ?? "package"})`,
        description: `Detected license ${name} for ${license.PkgName ?? "package"}. Policy status: ${policyStatus}.`,
        packageName: license.PkgName,
        source: "trivy",
        confidence: "medium",
        remediation: policyStatus === "blocked" ? "License is blocked by policy; replace or obtain an exception." : policyStatus === "review" ? "License requires review per policy." : undefined
      }));
    }
  }
  return findings;
}

// ---------- external scanner runners (timeout-guarded) ----------

function elapsed(startedAt: string): number {
  return Date.now() - new Date(startedAt).getTime();
}

function runExternal(command: string, args: string[], cwd: string, timeoutMs: number): { status: number; stdout: string; stderr: string; timedOut: boolean } {
  const result = spawnTool(command, args, { cwd, timeoutMs, maxBuffer: 64 * 1024 * 1024 });
  const errnoCode = result.error && "code" in result.error ? (result.error as NodeJS.ErrnoException).code : undefined;
  return { status: result.status ?? 1, stdout: result.stdout ?? "", stderr: redact(result.stderr ?? ""), timedOut: errnoCode === "ETIMEDOUT" };
}

function runGitleaks(projectPath: string, command: string, timeoutMs: number): ScannerResult {
  const startedAt = now();
  const reportDir = mkdtempSync(path.join(os.tmpdir(), "riskradar-gitleaks-"));
  const reportPath = path.join(reportDir, "report.json");
  try {
    const result = runExternal(command, ["detect", "--source", projectPath, "--no-git", "--no-banner", "--report-format", "json", "--report-path", reportPath], projectPath, timeoutMs);
    if (result.timedOut) {
      return { scanner: "gitleaks", category: "secret", status: "error", startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings: [], errors: [`gitleaks timed out after ${timeoutMs}ms`], complete: false };
    }
    // gitleaks exits non-zero when leaks are found; the report still parses.
    const findings = existsSync(reportPath) ? parseGitleaksJson(readFileSync(reportPath, "utf8")) : [];
    return { scanner: "gitleaks", category: "secret", status: "completed", version: probeVersion(command), startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings, errors: result.stderr ? [result.stderr.slice(0, 300)] : [], complete: true };
  } finally {
    rmSync(reportDir, { recursive: true, force: true });
  }
}

function runSemgrep(projectPath: string, command: string, timeoutMs: number): ScannerResult {
  const startedAt = now();
  const result = command === WSL_SEMGREP
    ? runSemgrepWsl(projectPath, timeoutMs)
    : runExternal(command, ["scan", "--json", "--quiet", "--metrics=off", "--config", "p/default", projectPath], projectPath, timeoutMs);
  if (result.timedOut) {
    return { scanner: "semgrep", category: "sast", status: "error", startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings: [], errors: [`semgrep timed out after ${timeoutMs}ms`], complete: false };
  }
  if (!result.stdout.trim()) {
    return { scanner: "semgrep", category: "sast", status: "error", startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings: [], errors: [result.stderr.slice(0, 300) || "semgrep produced no output"], complete: false };
  }
  const version = command === WSL_SEMGREP ? semgrepWslVersion() : probeVersion(command);
  return { scanner: "semgrep", category: "sast", status: "completed", version, startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings: parseSemgrepJson(result.stdout), errors: [], complete: true };
}

/** Runs Semgrep inside WSL against a Windows project path (translated to /mnt). */
function runSemgrepWsl(projectPath: string, timeoutMs: number): { status: number; stdout: string; stderr: string; timedOut: boolean } {
  const wslPath = toWslPath(projectPath);
  const shell = `cd '${wslPath.replace(/'/g, "'\\''")}' && ${WSL_SEMGREP_BIN} scan --json --quiet --metrics=off --config p/default .`;
  const r = spawnSync("wsl", ["bash", "-lc", shell], { encoding: "utf8", timeout: timeoutMs, maxBuffer: 64 * 1024 * 1024 });
  const errnoCode = r.error && "code" in r.error ? (r.error as NodeJS.ErrnoException).code : undefined;
  return { status: r.status ?? 1, stdout: r.stdout ?? "", stderr: redact(r.stderr ?? ""), timedOut: errnoCode === "ETIMEDOUT" };
}

function runTrivyFs(projectPath: string, command: string, timeoutMs: number): ScannerResult {
  const startedAt = now();
  const result = runExternal(command, ["fs", "--format", "json", "--quiet", "--scanners", "vuln,misconfig,secret,license", projectPath], projectPath, timeoutMs);
  if (result.timedOut) {
    return { scanner: "trivy", category: "container", status: "error", startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings: [], errors: [`trivy timed out after ${timeoutMs}ms`], complete: false };
  }
  if (!result.stdout.trim()) {
    return { scanner: "trivy", category: "container", status: "error", startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings: [], errors: [result.stderr.slice(0, 300) || "trivy produced no output"], complete: false };
  }
  return { scanner: "trivy", category: "container", status: "completed", version: probeVersion(command), startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings: parseTrivyJson(result.stdout, { licensePolicy: loadLicensePolicy() }), errors: [], complete: true };
}

/**
 * Scans a container image with Trivy (explicit opt-in: caller must supply an
 * image; RiskRadar never pulls/scans images by default). Returns tool_missing
 * when Trivy is absent.
 */
export function scanContainerImage(image: string, timeoutMs = scannerTimeoutMs()): ScannerResult {
  const tool = detectScannerTools().find((t) => t.id === "trivy")!;
  if (tool.status !== "enabled") {
    return { scanner: "trivy", category: "container", status: tool.status === "disabled" ? "disabled" : "tool_missing", findings: [], errors: [], installHint: tool.installHint, complete: false };
  }
  const startedAt = now();
  const result = runExternal(tool.command, ["image", "--format", "json", "--quiet", "--scanners", "vuln", image], process.cwd(), timeoutMs);
  if (result.timedOut) return { scanner: "trivy", category: "container", status: "error", startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings: [], errors: [`trivy image timed out after ${timeoutMs}ms`], complete: false };
  if (!result.stdout.trim()) return { scanner: "trivy", category: "container", status: "error", startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings: [], errors: [result.stderr.slice(0, 300) || "trivy image produced no output"], complete: false };
  return { scanner: "trivy", category: "container", status: "completed", startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings: parseTrivyJson(result.stdout), errors: [], complete: true };
}

// ---------- coverage (dashboard) ----------

export interface ScannerCoverageEntry {
  category: ScannerCategory;
  label: string;
  status: ScannerStatus;
  scanner: string;
  confidence: "high" | "medium" | "low";
  message: string;
  installHint?: string;
}

function toolInfo(id: string): ScannerToolInfo {
  return detectScannerTools().find((tool) => tool.id === id)!;
}

/**
 * Honest, run-free coverage for the dashboard. Each category reports the scanner
 * that *would* run and its real status — green only when a real check can run.
 */
export function scannerCoverage(projectPath?: string): ScannerCoverageEntry[] {
  const tools = detectScannerTools();
  const get = (id: string) => tools.find((tool) => tool.id === id)!;
  const hasWorkflows = projectPath ? existsSync(path.join(projectPath, ".github", "workflows")) : true;
  const gitleaks = get("gitleaks");
  const semgrep = get("semgrep");
  const trivy = get("trivy");
  const syft = get("syft");
  const osvScanner = get("osv-scanner");
  return [
    {
      category: "sca",
      label: "Dependency / SCA",
      status: "enabled",
      scanner: osvScanner.status === "enabled" ? "osv-scanner + OSV API" : "OSV API",
      confidence: osvScanner.status === "enabled" ? "high" : "medium",
      message: osvScanner.status === "enabled" ? "Lockfile/transitive scanning via OSV-Scanner plus OSV API." : "Direct-manifest scanning via OSV API. Install OSV-Scanner for lockfile/transitive coverage.",
      installHint: osvScanner.status === "enabled" ? undefined : osvScanner.installHint
    },
    gitleaks.status === "enabled"
      ? { category: "secret", label: "Secrets", status: "enabled", scanner: "gitleaks", confidence: "high", message: "Authoritative secret scanning via Gitleaks." }
      : { category: "secret", label: "Secrets", status: "enabled", scanner: "riskradar-secrets-lite", confidence: "low", message: "Lightweight built-in regex detector (low confidence). Install Gitleaks for authoritative scanning.", installHint: gitleaks.installHint },
    semgrep.status === "enabled"
      ? { category: "sast", label: "SAST", status: "enabled", scanner: "semgrep", confidence: "high", message: "Static analysis via Semgrep (config auto)." }
      : { category: "sast", label: "SAST", status: semgrep.status === "disabled" ? "disabled" : "tool_missing", scanner: "semgrep", confidence: "high", message: semgrep.status === "disabled" ? "Semgrep disabled by config." : "Semgrep not installed.", installHint: semgrep.installHint },
    trivy.status === "enabled"
      ? { category: "container", label: "Container / IaC", status: "enabled", scanner: "trivy", confidence: "high", message: "Filesystem/IaC/secret/license scanning via Trivy." }
      : { category: "container", label: "Container / IaC", status: trivy.status === "disabled" ? "disabled" : "tool_missing", scanner: "trivy", confidence: "high", message: trivy.status === "disabled" ? "Trivy disabled by config." : "Trivy not installed.", installHint: trivy.installHint },
    {
      category: "ci",
      label: "GitHub Actions / CI hardening",
      status: hasWorkflows ? "enabled" : "not_applicable",
      scanner: "riskradar-ci-hardening",
      confidence: "medium",
      message: hasWorkflows ? "Built-in static workflow hardening rules." : "No .github/workflows found."
    },
    {
      category: "agent",
      label: "Agent / MCP config",
      status: "enabled",
      scanner: "riskradar-agent-config",
      confidence: "medium",
      message: "Built-in Codex/MCP/GitHub Actions config risk checks."
    },
    {
      category: "malware",
      label: "Malicious / suspicious package",
      status: "enabled",
      scanner: "riskradar-quarantine",
      confidence: getEnv("RISKRADAR_MALICIOUS_PACKAGES_DIR") ? "high" : "low",
      message: getEnv("RISKRADAR_MALICIOUS_PACKAGES_DIR") ? "Matches against configured OpenSSF malicious-package data + lifecycle-script heuristics." : "Lifecycle-script + heuristic checks only. Set RISKRADAR_MALICIOUS_PACKAGES_DIR for authoritative malicious-package matching.",
      installHint: getEnv("RISKRADAR_MALICIOUS_PACKAGES_DIR") ? undefined : "Set RISKRADAR_MALICIOUS_PACKAGES_DIR to an OpenSSF malicious-packages data directory."
    },
    trivy.status === "enabled"
      ? { category: "license", label: "License", status: "enabled", scanner: "trivy", confidence: "medium", message: "License detection via Trivy." }
      : { category: "license", label: "License", status: "not_configured", scanner: "trivy", confidence: "medium", message: "License scanning needs Trivy.", installHint: trivy.installHint },
    syft.status === "enabled"
      ? { category: "sbom", label: "SBOM", status: "enabled", scanner: "syft", confidence: "high", message: "SBOM generation via Syft." }
      : trivy.status === "enabled"
        ? { category: "sbom", label: "SBOM", status: "enabled", scanner: "trivy", confidence: "high", message: "SBOM via Trivy." }
        : { category: "sbom", label: "SBOM", status: syft.status === "disabled" ? "disabled" : "tool_missing", scanner: "syft", confidence: "high", message: "SBOM generation needs Syft or Trivy.", installHint: syft.installHint }
  ];
}

// ---------- orchestration ----------

export interface RunScannersOptions {
  categories?: ScannerCategory[];
  maliciousDir?: string;
  timeoutMs?: number;
}

/**
 * Runs all applicable, enabled scanners against a project path and returns one
 * ScannerResult per scanner. Built-in scanners always run; external scanners run
 * only when their tool is installed (otherwise honest tool_missing).
 */
export function runProjectScanners(projectPath: string, projectId?: string, options: RunScannersOptions = {}): ScannerResult[] {
  const timeoutMs = options.timeoutMs ?? scannerTimeoutMs();
  const tools = detectScannerTools();
  const want = (category: ScannerCategory) => !options.categories || options.categories.includes(category);
  const results: ScannerResult[] = [];

  const builtin = (scanner: string, category: ScannerCategory, run: () => ScannerFinding[]): ScannerResult => {
    const startedAt = now();
    try {
      const findings = run();
      return { scanner, category, status: "completed", startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings, errors: [], complete: true };
    } catch (error) {
      return { scanner, category, status: "error", startedAt, finishedAt: now(), durationMs: elapsed(startedAt), findings: [], errors: [redact(error instanceof Error ? error.message : String(error))], complete: false };
    }
  };

  // Secrets: prefer Gitleaks, else lightweight built-in.
  if (want("secret")) {
    const gitleaks = tools.find((tool) => tool.id === "gitleaks")!;
    if (gitleaks.status === "enabled") results.push(runGitleaks(projectPath, gitleaks.command, timeoutMs));
    else results.push(builtin("riskradar-secrets-lite", "secret", () => scanSecretsLightweight(projectPath)));
  }
  if (want("ci")) {
    if (existsSync(path.join(projectPath, ".github", "workflows"))) results.push(builtin("riskradar-ci-hardening", "ci", () => scanCiHardening(projectPath)));
    else results.push({ scanner: "riskradar-ci-hardening", category: "ci", status: "not_applicable", findings: [], errors: [], complete: true });
  }
  if (want("agent")) {
    results.push(builtin("riskradar-agent-config", "agent", () => scanAgentConfig(projectPath, projectId).map((finding) => makeFinding({
      scanner: "riskradar-agent-config",
      category: "agent",
      severity: finding.severity,
      title: finding.reason,
      description: finding.recommendation,
      evidencePath: finding.filePath,
      evidenceLine: finding.line,
      redactedEvidence: finding.redactedSnippet,
      source: "riskradar-agent-config",
      confidence: "medium",
      remediation: finding.recommendation
    }))));
  }
  if (want("malware")) {
    results.push(builtin("riskradar-quarantine", "malware", () => scanMaliciousPackages(projectPath, { maliciousDir: options.maliciousDir })));
  }
  if (want("sast")) {
    const semgrep = tools.find((tool) => tool.id === "semgrep")!;
    if (semgrep.status === "enabled") results.push(runSemgrep(projectPath, semgrep.command, timeoutMs));
    else results.push({ scanner: "semgrep", category: "sast", status: semgrep.status === "disabled" ? "disabled" : "tool_missing", findings: [], errors: [], installHint: semgrep.installHint, complete: false });
  }
  if (want("container") || want("iac") || want("license")) {
    const trivy = tools.find((tool) => tool.id === "trivy")!;
    if (trivy.status === "enabled") results.push(runTrivyFs(projectPath, trivy.command, timeoutMs));
    else results.push({ scanner: "trivy", category: "container", status: trivy.status === "disabled" ? "disabled" : "tool_missing", findings: [], errors: [], installHint: trivy.installHint, complete: false });
  }
  return results;
}

export { toolInfo as scannerToolInfo };
