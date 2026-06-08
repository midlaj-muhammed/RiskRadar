import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import { getEnv, logDir } from "./env";
import { RiskRadarError } from "./errors";
import { redact } from "./redaction";

export function runGit(args: string[], cwd: string, allowFailure = false): { stdout: string; stderr: string; status: number } {
  const result = spawnSync("git", args, { cwd, encoding: "utf8" });
  const output = {
    stdout: redact(result.stdout ?? ""),
    stderr: redact(result.stderr ?? ""),
    status: result.status ?? 1
  };
  if (!allowFailure && output.status !== 0) {
    throw new RiskRadarError("git_command_failed", `git ${args[0]} failed.`, { args: args.slice(0, 2), stderr: output.stderr });
  }
  return output;
}

export function initBaselineRepo(workspace: string): void {
  runGit(["init"], workspace);
  runGit(["config", "user.email", "riskradar@example.invalid"], workspace);
  runGit(["config", "user.name", "RiskRadar"], workspace);
  runGit(["add", "-A"], workspace);
  runGit(["commit", "-m", "riskradar baseline"], workspace, true);
}

export function changedFiles(workspace: string): string[] {
  const unstaged = runGit(["diff", "--name-only"], workspace, true).stdout.split(/\r?\n/).filter(Boolean);
  const staged = runGit(["diff", "--cached", "--name-only"], workspace, true).stdout.split(/\r?\n/).filter(Boolean);
  const untracked = runGit(["ls-files", "--others", "--exclude-standard"], workspace, true).stdout.split(/\r?\n/).filter(Boolean);
  return [...new Set([...unstaged, ...staged, ...untracked])];
}

export const COMMIT_GITIGNORE_ENTRIES = [
  "node_modules/",
  ".env",
  ".env.*",
  "*.pem",
  "*.key",
  "*.p8",
  "*.p12",
  ".npmrc",
  ".yarnrc",
  ".pnpm-store/",
  "dist/",
  "build/",
  "coverage/",
  ".turbo/",
  ".next/"
];

const UNSAFE_COMMIT_PATTERNS = [
  /^node_modules\//,
  /^\.env($|\.)/,
  /^\.npmrc$/,
  /^\.yarnrc$/,
  /^\.pnpm-store\//,
  /^dist\//,
  /^build\//,
  /^coverage\//,
  /^\.turbo\//,
  /^\.next\//,
  /^\.riskradar\//,
  /^riskradar-context\.json$/,
  /^logs?\//,
  /(^|\/)[^/]*(secret|token|private[-_.]?key)[^/]*$/i,
  /\.(pem|key|p8|p12)$/i,
  /\.(log|tmp)$/i
];

export function ensureCommitGitignore(workspace: string): void {
  const gitignorePath = path.join(workspace, ".gitignore");
  const current = existsSync(gitignorePath) ? readFileSync(gitignorePath, "utf8") : "";
  const lines = current.split(/\r?\n/);
  const missing = COMMIT_GITIGNORE_ENTRIES.filter((entry) => !lines.includes(entry));
  if (missing.length === 0) return;
  const prefix = current.trim().length > 0 ? current.replace(/\s*$/, "\n") : "";
  writeFileSync(gitignorePath, `${prefix}${missing.join("\n")}\n`);
}

export function cleanupValidationArtifacts(workspace: string): void {
  for (const relative of ["node_modules", ".pnpm-store", ".turbo", ".next", "coverage", "dist", "build"]) {
    rmSync(path.join(workspace, relative), { recursive: true, force: true });
  }
}

export function unsafeCommitFiles(files: string[]): string[] {
  return files
    .map((file) => file.replace(/\\/g, "/"))
    .filter((file) => UNSAFE_COMMIT_PATTERNS.some((pattern) => pattern.test(file)));
}

export function assertSafeCommitState(workspace: string, files = changedFiles(workspace)): void {
  const unsafe = unsafeCommitFiles(files);
  if (unsafe.length > 0) {
    throw new RiskRadarError("unsafe_commit_files", "Unsafe generated or secret-like files are present; PR/patch creation is blocked.", { files: unsafe });
  }
}

export function writePatch(workspace: string, jobId: string, includeFiles?: string[]): string {
  assertSafeCommitState(workspace);
  assertSafeCommitState(workspace, includeFiles && includeFiles.length > 0 ? includeFiles : changedFiles(workspace));
  if (includeFiles && includeFiles.length > 0) {
    runGit(["add", "--", ...includeFiles], workspace);
  } else {
    runGit(["add", "-A"], workspace);
  }
  const patch = runGit(["diff", "--cached", "--binary"], workspace, true).stdout;
  runGit(["reset"], workspace, true);
  if (!patch.trim()) {
    throw new RiskRadarError("patch_empty", "Patch artifact was empty; no PR-ready local patch was created.", { jobId });
  }
  const patchDir = path.join(logDir(), "patches");
  mkdirSync(patchDir, { recursive: true });
  const patchPath = path.join(patchDir, `${jobId}.patch`);
  writeFileSync(patchPath, patch);
  return patchPath;
}

export function commitAll(workspace: string, message: string, includeFiles?: string[]): void {
  const files = includeFiles && includeFiles.length > 0 ? includeFiles : changedFiles(workspace);
  assertSafeCommitState(workspace);
  assertSafeCommitState(workspace, files);
  if (files.length === 0) throw new RiskRadarError("commit_empty", "No safe files are available to commit.");
  runGit(["add", "--", ...files], workspace);
  assertSafeCommitState(workspace, runGit(["diff", "--cached", "--name-only"], workspace, true).stdout.split(/\r?\n/).filter(Boolean));
  runGit(["commit", "-m", message], workspace);
}

export function tokenizedGithubRemote(owner: string, repo: string): string {
  const token = getEnv("GITHUB_TOKEN");
  if (!token) throw new RiskRadarError("github_token_missing", "Set GITHUB_TOKEN to clone/push GitHub remediation branches.", { requiredEnv: "GITHUB_TOKEN" });
  return `https://x-access-token:${token}@github.com/${owner}/${repo}.git`;
}

export function cloneGithubRepo(input: { owner: string; repo: string; branch: string; workspace: string; remoteUrl?: string }): void {
  const remote = input.remoteUrl && isLocalGitRemote(input.remoteUrl) ? input.remoteUrl : tokenizedGithubRemote(input.owner, input.repo);
  runGit(["clone", "--depth=1", "--branch", input.branch, remote, input.workspace], process.cwd());
  scrubGithubRemote(input.workspace, input.owner, input.repo);
}

export function pushBranch(workspace: string, branchName: string, owner?: string, repo?: string): void {
  if (owner && repo) runGit(["remote", "set-url", "origin", tokenizedGithubRemote(owner, repo)], workspace);
  try {
    runGit(["push", "origin", `HEAD:${branchName}`], workspace);
  } finally {
    if (owner && repo) scrubGithubRemote(workspace, owner, repo);
  }
}

export function createBranch(workspace: string, branchName: string): void {
  runGit(["checkout", "-B", branchName], workspace);
}

export function applyPatch(targetPath: string, patchPath: string, reverse = false, threeWay = false): void {
  // --3way applies via the patch's blob ancestry (index lines) and 3-way merges,
  // which survives CRLF/LF normalization differences between clones — needed when
  // re-applying a stashed lockfile patch to a fresh clone in the two-step push gate.
  const args = ["apply", ...(reverse ? ["--reverse"] : []), ...(threeWay ? ["--3way"] : []), patchPath];
  runGit(args, targetPath);
}

export function scrubGithubRemote(workspace: string, owner: string, repo: string): void {
  runGit(["remote", "set-url", "origin", `https://github.com/${owner}/${repo}.git`], workspace, true);
}

function isLocalGitRemote(remoteUrl: string): boolean {
  return remoteUrl.startsWith("file://") || path.isAbsolute(remoteUrl);
}
