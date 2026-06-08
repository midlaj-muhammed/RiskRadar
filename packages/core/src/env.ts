import { copyFileSync, existsSync, readFileSync } from "node:fs";
import os from "node:os";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { loadSecretsFile } from "./secrets";
import type { IntegrationHealth } from "./types";

loadDotenv();
// After .env: fill any remaining secrets from a configured secret-manager file
// (Docker/K8s secret mount or Vault file sink). Explicit env/.env values win.
loadSecretsFile();

function loadDotenv() {
  let current = process.cwd();
  for (let i = 0; i < 6; i += 1) {
    const candidate = path.join(current, ".env");
    if (existsSync(candidate)) {
      const lines = readFileSync(candidate, "utf8").split(/\r?\n/);
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
        const [key, ...rest] = trimmed.split("=");
        const name = key?.trim();
        if (!name || process.env[name] !== undefined) continue;
        process.env[name] = rest.join("=").trim().replace(/^["']|["']$/g, "");
      }
      return;
    }
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}

export function getEnv(name: string): string | undefined {
  const value = process.env[name] ?? aliasEnv(name);
  return value && value.trim().length > 0 ? value : undefined;
}

function aliasEnv(name: string): string | undefined {
  if (name === "APPROVAL_HMAC_SECRET") return process.env.APPROVAL_SIGNING_SECRET;
  if (name === "TELEGRAM_ALLOWED_CHAT_IDS") return process.env.TELEGRAM_CHAT_ID;
  return undefined;
}

export function repoRoot(): string {
  let current = process.cwd();
  for (let i = 0; i < 8; i += 1) {
    if (existsSync(path.join(current, "pnpm-workspace.yaml")) || existsSync(path.join(current, "MANIFEST.json"))) {
      return current;
    }
    const parent = path.dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return process.cwd();
}

export function dataFilePath(): string {
  // Demo mode (hosted preview): always read the bundled seed, regardless of any
  // RISKRADAR_DATA_FILE in a local .env. Work on a throwaway temp copy so the
  // committed demo/seed.json is never mutated by any write.
  if (getEnv("RISKRADAR_DEMO") === "true") {
    const seedRel = getEnv("RISKRADAR_DATA_FILE") ?? "demo/seed.json";
    const seedSrc = path.isAbsolute(seedRel) ? seedRel : path.resolve(repoRoot(), seedRel);
    const work = path.join(os.tmpdir(), "riskradar-demo.db.json");
    try {
      if (!existsSync(work) && existsSync(seedSrc)) copyFileSync(seedSrc, work);
    } catch { /* fall back to reading the seed directly */ }
    return existsSync(work) ? work : seedSrc;
  }
  const configured = getEnv("RISKRADAR_DATA_FILE") ?? ".riskradar/riskradar.db.json";
  return path.isAbsolute(configured) ? configured : path.resolve(repoRoot(), configured);
}

export function logDir(): string {
  const configured = getEnv("RISKRADAR_LOG_DIR") ?? ".riskradar/logs";
  return path.isAbsolute(configured) ? configured : path.resolve(repoRoot(), configured);
}

export function workspaceDir(): string {
  const configured = getEnv("RISKRADAR_WORKSPACE_DIR") ?? ".riskradar/workspaces";
  return path.isAbsolute(configured) ? configured : path.resolve(repoRoot(), configured);
}

export function localRoots(): string[] {
  return (getEnv("RISKRADAR_LOCAL_ROOTS") ?? "")
    .split(path.delimiter)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export function commandExists(command: string): boolean {
  if (path.isAbsolute(command)) return existsSync(command);
  const result = spawnSync(process.platform === "win32" ? "where.exe" : "command", process.platform === "win32" ? [command] : ["-v", command], {
    encoding: "utf8",
    shell: process.platform !== "win32"
  });
  return result.status === 0;
}

export function integrationHealth(): IntegrationHealth[] {
  const codexBin = getEnv("CODEX_BIN") ?? "codex";
  const syftBin = getEnv("SYFT_BIN") ?? "syft";
  return [
    {
      name: "Local database",
      status: "available",
      message: `Using file-backed local persistence at ${dataFilePath()}`
    },
    {
      name: "GitHub",
      status: getEnv("GITHUB_TOKEN") ? "configured" : "not_configured",
      message: getEnv("GITHUB_TOKEN") ? "GitHub API calls are enabled." : "Set GITHUB_TOKEN to validate repos and create PRs.",
      requiredEnv: ["GITHUB_TOKEN"]
    },
    {
      name: "OSV API",
      status: "configured",
      message: `Using ${getEnv("OSV_API_URL") ?? "https://api.osv.dev/v1/querybatch"} for fallback scans.`
    },
    {
      name: "OSV-Scanner CLI",
      status: commandExists("osv-scanner") ? "available" : "unavailable",
      message: commandExists("osv-scanner") ? "osv-scanner CLI is available." : "Install osv-scanner for lockfile-accurate recursive scans."
    },
    {
      name: "EPSS",
      status: "configured",
      message: `Using ${getEnv("EPSS_API_URL") ?? "https://api.first.org/data/v1/epss"} when CVEs exist.`
    },
    {
      name: "CISA KEV",
      status: "configured",
      message: `Using ${getEnv("CISA_KEV_URL") ?? "CISA KEV JSON feed"} for active exploitation enrichment.`
    },
    {
      name: "Codex CLI",
      status: commandExists(codexBin) ? "available" : "unavailable",
      message: commandExists(codexBin) ? `${codexBin} is available.` : `Install/authenticate Codex CLI or set CODEX_BIN.`
    },
    {
      name: "OpenAI SDK",
      status: getEnv("OPENAI_API_KEY") ? "configured" : "not_configured",
      message: getEnv("OPENAI_API_KEY") ? "OpenAI SDK Responses API adapter is enabled." : "Set OPENAI_API_KEY to use the OpenAI SDK remediation-plan adapter.",
      requiredEnv: ["OPENAI_API_KEY"]
    },
    {
      name: "Vercel AI SDK",
      status: getEnv("AI_GATEWAY_API_KEY") || getEnv("VERCEL_OIDC_TOKEN") ? "configured" : "not_configured",
      message: getEnv("AI_GATEWAY_API_KEY") || getEnv("VERCEL_OIDC_TOKEN")
        ? "AI Gateway adapter is enabled."
        : "Set AI_GATEWAY_API_KEY or VERCEL_OIDC_TOKEN to use AI SDK provider/model routing.",
      requiredEnv: ["AI_GATEWAY_API_KEY", "VERCEL_OIDC_TOKEN"]
    },
    {
      name: "Telegram",
      status: getEnv("TELEGRAM_BOT_TOKEN") && getEnv("APPROVAL_HMAC_SECRET") ? "configured" : "not_configured",
      message: getEnv("TELEGRAM_BOT_TOKEN") && getEnv("APPROVAL_HMAC_SECRET")
        ? "Telegram approval requests are enabled."
        : "Set TELEGRAM_BOT_TOKEN, TELEGRAM_ALLOWED_CHAT_IDS, and APPROVAL_HMAC_SECRET.",
      requiredEnv: ["TELEGRAM_BOT_TOKEN", "TELEGRAM_ALLOWED_CHAT_IDS", "APPROVAL_HMAC_SECRET"]
    },
    {
      name: "Vercel",
      status: getEnv("VERCEL_TOKEN") ? "configured" : "not_configured",
      message: getEnv("VERCEL_TOKEN") ? "Vercel API can be used for deployment lookups." : "Set VERCEL_TOKEN for real deployment API lookups; local .vercel mapping still works.",
      requiredEnv: ["VERCEL_TOKEN"]
    },
    {
      name: "OpenClaw",
      status: getEnv("OPENCLAW_ENABLED") === "true" && commandExists(getEnv("OPENCLAW_BIN") ?? "openclaw") ? "available" : "not_configured",
      message: "OpenClaw is optional. Enable with OPENCLAW_ENABLED=true and install the OpenClaw CLI."
    },
    {
      name: "SBOM",
      status: commandExists(syftBin) ? "available" : "unavailable",
      message: commandExists(syftBin) ? `${syftBin} is available for SBOM generation.` : "Install Syft or set SYFT_BIN for real SBOM generation."
    },
    {
      name: "Local roots",
      status: localRoots().some((root) => existsSync(root)) ? "configured" : "not_configured",
      message: localRoots().length > 0 ? `Allowed roots: ${localRoots().join(", ")}` : "Set RISKRADAR_LOCAL_ROOTS before adding local folders."
    }
  ];
}
