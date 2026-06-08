import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { spawn, spawnSync } from "node:child_process";
import path from "node:path";
import { commandExists, getEnv } from "./env";
import { RiskRadarError } from "./errors";
import { redact } from "./redaction";

export const CODEX_REMEDIATION_PROMPT = `You are RiskRadar, a security remediation worker.

Your task is to fix exactly one dependency vulnerability in this repository.

Read riskradar-context.json before editing files.

Rules:
1. Make the smallest safe dependency update that resolves the vulnerability.
2. Prefer patch/minor upgrades over major upgrades.
3. Do not refactor unrelated code.
4. Do not remove or weaken tests.
5. Do not edit secrets, environment files, credentials, CI tokens, or deployment secrets.
6. Do not change unrelated formatting across the repo.
7. If tests fail because of the dependency upgrade, fix only the code needed for compatibility.
8. If a safe fix cannot be made, stop and explain why.
9. Stop before merge or deployment.
10. Return a clear summary of changed files, commands run, and remaining risk.

Required workflow:
1. Inspect package manifest and lockfile.
2. Identify the vulnerable package and fixed version from riskradar-context.json.
3. Apply the minimal dependency update.
4. Update lockfile correctly.
5. Run the validation commands from riskradar-context.json if available.
6. Report validation results.
7. Provide a PR-ready summary.

Output format:
- Summary
- Files changed
- Dependency changes
- Commands run
- Validation result
- Remaining risk`;

const TEN_MINUTES_MS = 10 * 60 * 1000;

/**
 * Compact, bounded remediation prompt used by `verify:codex-live`. It instructs
 * Codex to perform a single manifest edit and explicitly forbids running any
 * commands, so RiskRadar itself stays in control of install/test/build. This is
 * the lever that keeps the live Codex task small enough to complete reliably.
 */
export function buildScopedCodexPrompt(input: { packageName: string; currentVersion: string; fixedVersion: string }): string {
  return `You are RiskRadar Codex worker. In this workspace, update package.json so ${input.packageName} moves from ${input.currentVersion} to ${input.fixedVersion}. Change only package.json. Do not edit package-lock.json. Do not run commands. Do not refactor. Stop after the edit.`;
}

export interface CodexCliResult {
  /** True when Codex exited 0 and did not time out. */
  ok: boolean;
  command: string;
  args: string[];
  status: number;
  stdout: string;
  stderr: string;
  durationMs: number;
  timedOut: boolean;
}

export interface CodexRemediationOutcome {
  codexStatus: "completed" | "timeout" | "quota_limited" | "rate_limited" | "auth_failed" | "failed" | "unavailable" | "no_changes";
  /** Real Codex completion: a finished job whose detected file changes were captured. */
  codexCompleted: boolean;
  /** Whether RiskRadar should run the deterministic fallback for this outcome. */
  shouldFallback: boolean;
}

/**
 * Classifies a remediation job into an honest Codex outcome. A job is only
 * reported as a real Codex completion when it reached a PR/patch-ready state
 * *and* RiskRadar actually detected changed files. Timeouts, failures, missing
 * Codex, and no-change runs all fall back to deterministic remediation.
 */
export function classifyCodexRemediation(
  job: { status?: string; errorCode?: string; changedFiles?: string[] } | undefined
): CodexRemediationOutcome {
  const errorCode = job?.errorCode ?? "";
  const changedFiles = job?.changedFiles ?? [];
  if (errorCode === "codex_timeout") return { codexStatus: "timeout", codexCompleted: false, shouldFallback: true };
  if (errorCode === "codex_quota_limited") return { codexStatus: "quota_limited", codexCompleted: false, shouldFallback: true };
  if (errorCode === "codex_rate_limited") return { codexStatus: "rate_limited", codexCompleted: false, shouldFallback: true };
  if (errorCode === "codex_auth_failed") return { codexStatus: "auth_failed", codexCompleted: false, shouldFallback: true };
  if (errorCode === "codex_unavailable" || errorCode === "codex_safety_unavailable") {
    return { codexStatus: "unavailable", codexCompleted: false, shouldFallback: true };
  }
  if (errorCode === "codex_no_changes") return { codexStatus: "no_changes", codexCompleted: false, shouldFallback: true };
  const reachedReady = job?.status === "pr_ready" || job?.status === "approval_sent";
  if (reachedReady && changedFiles.length > 0) {
    return { codexStatus: "completed", codexCompleted: true, shouldFallback: false };
  }
  return { codexStatus: "failed", codexCompleted: false, shouldFallback: true };
}

export function codexStatus(): { configured: boolean; message: string } {
  const bin = getEnv("CODEX_BIN") ?? "codex";
  if (getEnv("CODEX_ENABLED") === "false") return { configured: false, message: "CODEX_ENABLED=false" };
  return commandExists(bin) ? { configured: true, message: `${bin} is available` } : { configured: false, message: `${bin} was not found on PATH` };
}

export function writeCodexContext(workspace: string, context: unknown): string {
  mkdirSync(workspace, { recursive: true });
  const file = path.join(workspace, "riskradar-context.json");
  writeFileSync(file, redact(context));
  return file;
}

/** Runs `codex --version`. Safe diagnostic: no prompt, short timeout. */
export function codexVersion(timeoutMs = 20000): Promise<CodexCliResult> {
  return spawnCodex(["--version"], { timeoutMs });
}

/** Runs `codex exec --help`. Safe diagnostic: no prompt, short timeout. */
export function codexExecHelp(timeoutMs = 20000): Promise<CodexCliResult> {
  return spawnCodex(["exec", "--help"], { timeoutMs });
}

/**
 * Runs a Codex prompt in a workspace using safe sandbox settings and a
 * secret-scrubbed environment. The prompt is always delivered through stdin so
 * multiline prompts stay a single input and are never shell-split into args.
 */
export async function runCodexPrompt(
  workspace: string,
  prompt = CODEX_REMEDIATION_PROMPT,
  options: { timeoutMs?: number } = {}
): Promise<CodexCliResult> {
  const status = codexStatus();
  if (!status.configured) {
    throw new RiskRadarError("codex_unavailable", `Codex not executed: ${status.message}`, { requiredTool: getEnv("CODEX_BIN") ?? "codex" });
  }
  if (!existsSync(workspace)) throw new RiskRadarError("workspace_missing", "Codex workspace does not exist.", { workspace });
  const safety = codexSafetyFlags();
  const timeoutMs = options.timeoutMs ?? Number(getEnv("CODEX_TIMEOUT_MS") ?? TEN_MINUTES_MS);
  return spawnCodex(codexExecArgs(workspace, safety), { input: prompt, timeoutMs });
}

/**
 * Backwards-compatible wrapper used by the remediation service. Returns the
 * fields callers already depend on, plus duration/timedOut for honest reporting.
 * Async so the agentic Codex run never blocks the Node event loop (a single
 * webhook server stays responsive to other taps while Codex works).
 */
export async function runCodexExec(
  workspace: string,
  prompt = CODEX_REMEDIATION_PROMPT,
  options: { timeoutMs?: number } = {}
): Promise<{ stdout: string; stderr: string; status: number; durationMs: number; timedOut: boolean }> {
  const result = await runCodexPrompt(workspace, prompt, options);
  return { stdout: result.stdout, stderr: result.stderr, status: result.status, durationMs: result.durationMs, timedOut: result.timedOut };
}

export function codexExecArgs(workspace: string, safety: string[]): string[] {
  return ["exec", "--cd", workspace, ...safety, "-"];
}

export function codexSafetyFlags(bin = getEnv("CODEX_BIN") ?? "codex"): string[] {
  const command = resolveCodexExecutable(bin);
  const invocation = codexInvocation(command, ["exec", "--help"]);
  const help = spawnSync(invocation.command, invocation.args, { encoding: "utf8", timeout: 10000 });
  const text = `${help.stdout ?? ""}\n${help.stderr ?? ""}`;
  if ((help.status ?? 1) !== 0 || !text.includes("--sandbox")) {
    throw new RiskRadarError("codex_safety_unavailable", "Codex not executed: this Codex CLI does not expose enforceable sandbox flags.", { requiredFlag: "--sandbox" });
  }
  const flags = ["--sandbox", "workspace-write", "--ephemeral", "--skip-git-repo-check"];
  if (text.includes("--ask-for-approval")) {
    flags.push("--ask-for-approval", "never");
  } else {
    flags.push("-c", "approval_policy=\"never\"");
  }
  return flags;
}

export function resolveCodexExecutable(bin: string): string {
  if (path.isAbsolute(bin) || bin.includes(path.sep)) return bin;
  if (process.platform !== "win32") return bin;
  const result = spawnSync("where.exe", [bin], { encoding: "utf8" });
  if ((result.status ?? 1) !== 0) return bin;
  const candidates = (result.stdout ?? "").split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
  // npm installs both an extensionless `codex` (a Git-Bash sh shim) and a
  // Windows-executable `codex.cmd`. spawnSync cannot run the extensionless shim
  // on Windows, so prefer .exe/.cmd/.bat before falling back.
  const windowsExecutable = [".exe", ".cmd", ".bat"];
  return (
    candidates.find((candidate) => windowsExecutable.some((ext) => candidate.toLowerCase().endsWith(ext))) ??
    candidates[0] ??
    bin
  );
}

function codexInvocation(bin: string, args: string[]): { command: string; args: string[] } {
  if (process.platform === "win32" && /\.(cmd|bat)$/i.test(bin)) {
    return { command: process.env.ComSpec ?? "cmd.exe", args: ["/d", "/c", "call", bin, ...args] };
  }
  return { command: bin, args };
}

/**
 * Secret-scrubbed environment for Codex. Passes through only what the CLI needs
 * to find its binary, its own auth/config (~/.codex via USERPROFILE/CODEX_HOME),
 * and the OS runtime. No GitHub/Telegram/approval secrets are ever forwarded.
 */
function codexChildEnv(): NodeJS.ProcessEnv {
  const passthrough = [
    "PATH",
    "Path",
    "HOME",
    "USERPROFILE",
    "APPDATA",
    "LOCALAPPDATA",
    "TEMP",
    "TMP",
    "SystemRoot",
    "ComSpec",
    "CODEX_HOME"
  ];
  const env: NodeJS.ProcessEnv = { NODE_ENV: process.env.NODE_ENV };
  for (const key of passthrough) {
    if (process.env[key] !== undefined) env[key] = process.env[key];
  }
  return env;
}

// Kills the whole child process tree. On Windows a `cmd /c call codex.cmd` child
// spawns the heavy Codex runtime as grandchildren, so child.kill() alone leaves
// them running — taskkill /T reaps the tree.
function killProcessTree(pid: number | undefined): void {
  if (!pid) return;
  if (process.platform === "win32") {
    spawn("taskkill", ["/PID", String(pid), "/T", "/F"]).on("error", () => undefined);
  } else {
    try { process.kill(-pid, "SIGKILL"); } catch { try { process.kill(pid, "SIGKILL"); } catch { /* already gone */ } }
  }
}

// Async Codex runner. Uses child_process.spawn (non-blocking) so the agentic
// Codex run never freezes the Node event loop; the prompt is delivered on stdin,
// and a timeout kills the process tree. Resolves (never rejects) with the same
// shape the sync version returned, so callers only add `await`.
function spawnCodex(args: string[], options: { input?: string; timeoutMs: number }): Promise<CodexCliResult> {
  const bin = resolveCodexExecutable(getEnv("CODEX_BIN") ?? "codex");
  const invocation = codexInvocation(bin, args);
  const started = Date.now();
  return new Promise<CodexCliResult>((resolve) => {
    let settled = false;
    let timedOut = false;
    let stdout = "";
    let stderr = "";
    const child = spawn(invocation.command, invocation.args, { env: codexChildEnv() });
    const timer = setTimeout(() => { timedOut = true; killProcessTree(child.pid); }, options.timeoutMs);
    const finish = (rawStatus: number) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      const status = timedOut ? 124 : rawStatus;
      resolve({
        ok: status === 0 && !timedOut,
        command: redact(invocation.command),
        args: invocation.args.map((arg) => redact(arg)),
        status,
        stdout: redact(stdout),
        stderr: timedOut ? `Codex execution timed out after ${options.timeoutMs}ms.` : redact(stderr),
        durationMs: Date.now() - started,
        timedOut
      });
    };
    child.stdout?.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr?.on("data", (chunk) => { stderr += chunk.toString(); });
    child.on("error", (error) => { stderr += `\n${(error as Error).message ?? String(error)}`; finish(1); });
    child.on("close", (code) => finish(code ?? 1));
    if (options.input !== undefined) child.stdin?.write(options.input);
    child.stdin?.end();
  });
}
