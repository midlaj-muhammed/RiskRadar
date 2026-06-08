import { spawnSync } from "node:child_process";
import { loadDotenvFile, optionalEnv, safeJson } from "./live-utils.ts";

loadDotenvFile();

const required = ["GITHUB_TOKEN", "RISKRADAR_TEST_REPO", "TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID", "TELEGRAM_WEBHOOK_SECRET", "APPROVAL_SIGNING_SECRET", "CODEX_TIMEOUT_MS"];
const missing = required.filter((key) => !optionalEnv(key));
if (missing.length > 0) {
  console.error(safeJson({ ok: false, missing, message: "Live demo not run; required env is missing." }));
  process.exit(1);
}

const steps = [
  "verify:live-readiness",
  "verify:github-live",
  "verify:github-pr-live",
  "verify:telegram-live"
];

if (optionalEnv("RISKRADAR_RUN_CODEX_LIVE") === "true") steps.push("verify:codex-live");

for (const step of steps) {
  const result = spawnSync("pnpm", [step], { stdio: "inherit", shell: process.platform === "win32" });
  if ((result.status ?? 1) !== 0) process.exit(result.status ?? 1);
}

if (optionalEnv("RISKRADAR_SMOKE_BASE_URL")) {
  const result = spawnSync("pnpm", ["smoke:app", optionalEnv("RISKRADAR_SMOKE_BASE_URL")!], { stdio: "inherit", shell: process.platform === "win32" });
  if ((result.status ?? 1) !== 0) process.exit(result.status ?? 1);
}

console.log(safeJson({ ok: true, steps, codexLiveRun: optionalEnv("RISKRADAR_RUN_CODEX_LIVE") === "true" }));
