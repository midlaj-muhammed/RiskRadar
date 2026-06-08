import { existsSync, readFileSync } from "node:fs";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import os from "node:os";
import path from "node:path";
import { redact } from "../packages/core/src/index.ts";

export interface TestRepo {
  owner: string;
  repo: string;
  url: string;
}

export function requiredEnv(name: string): string {
  const value = process.env[name];
  if (!value || value.trim().length === 0) throw new Error(`Missing required env: ${name}`);
  return value.trim();
}

export function optionalEnv(name: string): string | undefined {
  const value = process.env[name];
  return value && value.trim().length > 0 ? value.trim() : undefined;
}

export function approvalSecret(): string {
  return requiredEnv("APPROVAL_SIGNING_SECRET");
}

export function telegramChatId(): string {
  return requiredEnv("TELEGRAM_CHAT_ID");
}

export function parseTestRepo(): TestRepo {
  const raw = requiredEnv("RISKRADAR_TEST_REPO");
  const match = raw.match(/github\.com[:/](?<owner>[^/\s]+)\/(?<repo>[^/\s#?]+?)(?:\.git)?(?:[?#].*)?$/i) ?? raw.match(/^(?<owner>[^/\s]+)\/(?<repo>[^/\s#?]+)$/);
  const owner = match?.groups?.owner;
  const repo = match?.groups?.repo?.replace(/\.git$/i, "");
  if (!owner || !repo) throw new Error("RISKRADAR_TEST_REPO must be a GitHub URL or owner/repo.");
  assertSafeDemoRepo(repo);
  return { owner, repo, url: raw };
}

export function assertSafeDemoRepo(repo: string): void {
  if (!/(riskradar-(test|demo)|riskradar.*(test|demo)|(test|demo).*riskradar)/i.test(repo)) {
    throw new Error("Refusing live run: repository name must clearly include riskradar-test or riskradar-demo.");
  }
}

export function redactedStatus(keys: string[]): Array<{ key: string; status: "***set***" | "missing" }> {
  return keys.map((key) => ({ key, status: optionalEnv(key) ? "***set***" : "missing" }));
}

export function loadDotenvFile(): void {
  const file = path.resolve(process.cwd(), ".env");
  if (!existsSync(file)) return;
  for (const line of readFileSync(file, "utf8").split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes("=")) continue;
    const [key, ...rest] = trimmed.split("=");
    const name = key?.trim();
    if (!name || process.env[name] !== undefined) continue;
    process.env[name] = rest.join("=").trim().replace(/^["']|["']$/g, "");
  }
}

export function commandAvailable(command: string): boolean {
  const result = spawnSync(process.platform === "win32" ? "where.exe" : "command", process.platform === "win32" ? [command] : ["-v", command], {
    encoding: "utf8",
    shell: process.platform !== "win32"
  });
  return result.status === 0;
}

export async function githubRequest(pathname: string, init: RequestInit = {}): Promise<Response> {
  const token = requiredEnv("GITHUB_TOKEN");
  return fetch(`https://api.github.com${pathname}`, {
    ...init,
    headers: {
      accept: "application/vnd.github+json",
      authorization: `Bearer ${token}`,
      "x-github-api-version": "2022-11-28",
      ...(init.headers ?? {})
    }
  });
}

export async function assertGithubRepoAccessible(repo = parseTestRepo()): Promise<{ defaultBranch: string; private: boolean }> {
  const response = await githubRequest(`/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}`);
  if (!response.ok) throw new Error(`GitHub repo access failed: HTTP ${response.status}`);
  const body = await response.json() as { default_branch?: string; private?: boolean; permissions?: { push?: boolean; pull?: boolean } };
  if (body.permissions && body.permissions.pull === false) throw new Error("GitHub token lacks repository read permission.");
  return { defaultBranch: body.default_branch ?? "main", private: Boolean(body.private) };
}

export async function assertGithubWritePermissions(repo = parseTestRepo()): Promise<void> {
  const response = await githubRequest(`/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}`);
  if (!response.ok) throw new Error(`GitHub repo access failed: HTTP ${response.status}`);
  const body = await response.json() as { permissions?: { push?: boolean } };
  if (body.permissions?.push === true) return;
  const userResponse = await githubRequest("/user");
  if (!userResponse.ok) throw new Error(`GitHub token user lookup failed: HTTP ${userResponse.status}`);
  const user = await userResponse.json() as { login?: string };
  if (!user.login) throw new Error("GitHub token user lookup did not return a login.");
  const permissionResponse = await githubRequest(`/repos/${encodeURIComponent(repo.owner)}/${encodeURIComponent(repo.repo)}/collaborators/${encodeURIComponent(user.login)}/permission`);
  if (!permissionResponse.ok) throw new Error(`GitHub permission lookup failed: HTTP ${permissionResponse.status}`);
  const permission = await permissionResponse.json() as { permission?: string };
  if (!["admin", "maintain", "write"].includes(permission.permission ?? "")) {
    throw new Error("GitHub token lacks required write permission for contents/pull requests.");
  }
  assertGitPushDryRunWorks(repo);
}

function assertGitPushDryRunWorks(repo: TestRepo): void {
  const token = requiredEnv("GITHUB_TOKEN");
  const root = mkdtempSync(path.join(os.tmpdir(), "riskradar-git-write-check-"));
  const remote = `https://github.com/${repo.owner}/${repo.repo}.git`;
  const basic = Buffer.from(`x-access-token:${token}`).toString("base64");
  try {
    run("git", ["init"], root);
    run("git", ["config", "user.email", "riskradar@example.invalid"], root);
    run("git", ["config", "user.name", "RiskRadar Live QA"], root);
    writeFileSync(path.join(root, "README.md"), "RiskRadar git write dry-run check\n");
    run("git", ["add", "README.md"], root);
    run("git", ["commit", "-m", "riskradar dry-run permission check"], root);
    run("git", ["remote", "add", "origin", remote], root);
    const result = spawnSync("git", ["-c", "credential.helper=", "-c", `http.extraHeader=Authorization: Basic ${basic}`, "push", "--dry-run", "origin", "HEAD:refs/heads/riskradar-permission-check"], {
      cwd: root,
      encoding: "utf8"
    });
    if ((result.status ?? 1) !== 0) {
      throw new Error(`GitHub token cannot push to the test repo: ${redact(result.stderr || result.stdout || "dry-run push failed")}`);
    }
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
}

function run(command: string, args: string[], cwd: string): void {
  const result = spawnSync(command, args, { cwd, encoding: "utf8" });
  if ((result.status ?? 1) !== 0) throw new Error(redact(result.stderr || result.stdout || `${command} failed`));
}

export async function assertTelegramBotWorks(): Promise<{ username?: string }> {
  const token = requiredEnv("TELEGRAM_BOT_TOKEN");
  const response = await fetch(`https://api.telegram.org/bot${token}/getMe`);
  const body = await response.json() as { ok?: boolean; result?: { username?: string }; description?: string };
  if (!response.ok || !body.ok) throw new Error(`Telegram getMe failed: HTTP ${response.status}`);
  return { username: body.result?.username };
}

export function safeJson(value: unknown): string {
  return redact(JSON.stringify(value, null, 2));
}
