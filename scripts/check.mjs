#!/usr/bin/env node
// Windows-friendly check orchestrator. Runs a named group of pnpm scripts /
// special steps sequentially and prints an honest pass/fail summary.
// Usage: node scripts/check.mjs <group>
import { spawn, spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";

const group = process.argv[2];

function envHas(...keys) {
  if (!existsSync(".env")) return false;
  const text = readFileSync(".env", "utf8");
  return keys.every((k) => new RegExp(`^${k}=.+`, "m").test(text));
}

function runPnpm(script) {
  process.stdout.write(`\n▶ pnpm ${script}\n`);
  const r = spawnSync("pnpm", ["-s", script], { stdio: "inherit", shell: process.platform === "win32" });
  return (r.status ?? 1) === 0;
}

async function pollHealth(url, tries = 45) {
  for (let i = 0; i < tries; i += 1) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(2000) });
      if (res.ok) return true;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 2000));
  }
  return false;
}

const SECRET_RE = [/gh[pousr]_[A-Za-z0-9_]{20,}/, /sk-[A-Za-z0-9_-]{20,}/, /xox[baprs]-[A-Za-z0-9-]{10,}/, /AKIA[0-9A-Z]{16}/, /\b\d{8,10}:[A-Za-z0-9_-]{30,}\b/];

async function checkUi() {
  if (!runPnpm("build")) return false;
  const port = 3030;
  const server = spawn("pnpm", ["--filter", "@riskradar/web", "exec", "next", "start", "--hostname", "127.0.0.1", "--port", String(port)], { shell: process.platform === "win32", detached: false });
  let ok = false;
  try {
    const up = await pollHealth(`http://127.0.0.1:${port}/api/health`);
    if (!up) { console.error("✗ server did not start"); return false; }
    const routes = ["/", "/scanners", "/watch", "/providers", "/settings", "/threat-radar", "/approval-queue"];
    ok = true;
    for (const route of routes) {
      const res = await fetch(`http://127.0.0.1:${port}${route}`);
      const body = await res.text();
      const leak = SECRET_RE.find((re) => re.test(body));
      const pass = res.status === 200 && !leak;
      console.log(`  ${pass ? "✓" : "✗"} ${route} -> ${res.status}${leak ? " LEAK!" : ""}`);
      if (!pass) ok = false;
    }
  } finally {
    try { if (server.pid) process.kill(server.pid); } catch { /* ignore */ }
    if (process.platform === "win32" && server.pid) spawnSync("taskkill", ["/pid", String(server.pid), "/T", "/F"], { stdio: "ignore" });
  }
  return ok;
}

function checkClean() {
  const tracked = spawnSync("git", ["ls-files", ".env"], { encoding: "utf8" }).stdout.trim();
  const envIgnored = spawnSync("git", ["check-ignore", ".env"], { encoding: "utf8" }).stdout.trim() === ".env";
  const trackedGenerated = spawnSync("git", ["ls-files"], { encoding: "utf8" }).stdout.split(/\r?\n/).filter((f) => /node_modules\/|\.next\/|\.riskradar\//.test(f));
  console.log(`  ${tracked === "" ? "✓" : "✗"} .env not tracked`);
  console.log(`  ${envIgnored ? "✓" : "✗"} .env ignored`);
  console.log(`  ${trackedGenerated.length === 0 ? "✓" : "✗"} no generated files tracked`);
  return tracked === "" && envIgnored && trackedGenerated.length === 0;
}

const GROUPS = {
  unit: () => runPnpm("test"),
  quick: () => ["typecheck", "lint", "test"].every(runPnpm),
  build: () => ["typecheck", "lint", "test", "build"].every(runPnpm),
  integration: () => ["verify:local-e2e", "verify:agent-provider", "verify:provider-chain", "verify:provider-failover-consent", "verify:watch-mode", "verify:scanner-tools", "verify:scanners"].every(runPnpm),
  demo: () => ["verify:local-e2e", "demo:scanner-coverage", "demo:watch", "demo:provider-failover", "demo:live"].every(runPnpm),
  security: () => ["audit:repo", "verify:env-redaction", "verify:scanner-tools", "verify:scanners"].every(runPnpm),
  ui: () => checkUi(),
  live: () => {
    if (!envHas("GITHUB_TOKEN", "RISKRADAR_TEST_REPO", "TELEGRAM_BOT_TOKEN", "APPROVAL_SIGNING_SECRET")) {
      console.log("⚠ check:live skipped — required live env not configured (GITHUB_TOKEN, RISKRADAR_TEST_REPO, TELEGRAM_BOT_TOKEN, APPROVAL_SIGNING_SECRET). Not faking success.");
      return true;
    }
    return ["verify:live-readiness", "demo:live", "demo:provider-failover"].every(runPnpm);
  },
  full: async () => {
    const steps = [["unit", GROUPS.unit], ["integration", GROUPS.integration], ["security", GROUPS.security], ["ui", GROUPS.ui]];
    let ok = true;
    for (const [name, fn] of steps) { console.log(`\n=== ${name} ===`); if (!(await fn())) ok = false; }
    console.log("\n=== live ==="); if (!(await GROUPS.live())) ok = false;
    return ok;
  },
  clean: async () => { console.log("=== clean-state checks ==="); const c = checkClean(); const f = await GROUPS.full(); return c && f; }
};

if (!group || !GROUPS[group]) {
  console.error(`Usage: node scripts/check.mjs <${Object.keys(GROUPS).join("|")}>`);
  process.exit(2);
}

const ok = await GROUPS[group]();
console.log(`\n${ok ? "✅" : "❌"} check:${group} ${ok ? "passed" : "FAILED"}`);
process.exit(ok ? 0 : 1);
