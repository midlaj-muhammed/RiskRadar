import { existsSync } from "node:fs";
import { assertGithubRepoAccessible, assertGithubWritePermissions, assertTelegramBotWorks, commandAvailable, loadDotenvFile, optionalEnv, parseTestRepo, redactedStatus, safeJson } from "./live-utils.ts";

loadDotenvFile();

const required = [
  "GITHUB_TOKEN",
  "RISKRADAR_TEST_REPO",
  "TELEGRAM_BOT_TOKEN",
  "TELEGRAM_CHAT_ID",
  "TELEGRAM_WEBHOOK_SECRET",
  "APPROVAL_SIGNING_SECRET",
  "CODEX_TIMEOUT_MS"
];

async function main() {
  const missing = required.filter((key) => !optionalEnv(key));
  const result: Record<string, unknown> = {
    ok: false,
    dotEnvExists: existsSync(".env"),
    env: redactedStatus(required),
    missing
  };
  if (missing.length > 0) {
    console.log(safeJson(result));
    process.exit(1);
  }

  const repo = parseTestRepo();
  const github = await assertGithubRepoAccessible(repo);
  await assertGithubWritePermissions(repo);
  const telegram = await assertTelegramBotWorks();
  const codexAvailable = commandAvailable(optionalEnv("CODEX_BIN") ?? "codex");
  const osvScannerAvailable = commandAvailable("osv-scanner");
  const localRootsConfigured = Boolean(optionalEnv("RISKRADAR_LOCAL_ROOTS"));

  console.log(safeJson({
    ok: true,
    repo: { owner: repo.owner, repo: repo.repo, defaultBranch: github.defaultBranch, private: github.private, writePermission: true },
    telegram: { getMe: "ok", username: telegram.username },
    codex: { available: codexAvailable },
    osvScanner: { available: osvScannerAvailable },
    localRoots: { configured: localRootsConfigured },
    env: redactedStatus(required)
  }));
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
