import { existsSync, readFileSync } from "node:fs";
import { loadDotenvFile, redactedStatus, safeJson } from "./live-utils.ts";

loadDotenvFile();

const keys = [
  "GITHUB_TOKEN",
  "RISKRADAR_TEST_REPO",
  "TELEGRAM_BOT_TOKEN",
  "TELEGRAM_CHAT_ID",
  "TELEGRAM_WEBHOOK_SECRET",
  "APPROVAL_SIGNING_SECRET",
  "CODEX_TIMEOUT_MS"
];

const gitignore = existsSync(".gitignore") ? readFileSync(".gitignore", "utf8") : "";
const ignored = [".env", ".env.*", "*.pem", "*.key", "*token*", "*secret*"].every((entry) => gitignore.includes(entry));

console.log(safeJson({
  ok: ignored,
  dotEnvExists: existsSync(".env"),
  gitignoreCoversLocalSecrets: ignored,
  env: redactedStatus(keys)
}));

if (!ignored) process.exit(1);
