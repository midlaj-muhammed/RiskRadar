import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  type CodexCliResult,
  buildScopedCodexPrompt,
  codexExecHelp,
  codexStatus,
  codexVersion,
  runCodexPrompt
} from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// verify:codex-cli is a diagnostic, not the live remediation. Give each Codex
// call enough room to finish a tiny task, but never less than an explicit
// CODEX_TIMEOUT_MS override.
const DIAGNOSTIC_TIMEOUT_MS = Math.max(Number(process.env.CODEX_TIMEOUT_MS ?? 0), 180000);

const NO_REPO_PROMPT = [
  "Reply with only the following JSON object and nothing else. Do not run any commands.",
  '{"ok":true,"message":"riskradar codex check"}'
].join("\n");

const FILE_EDIT_PROMPT = [
  "In this workspace there is a file named codex-check.txt that currently contains the single word: before.",
  "Change codex-check.txt so its only contents are the word: after.",
  "Change only codex-check.txt. Do not edit any other file. Do not run any commands. Stop after the edit."
].join("\n");

/** Detects external (non-code) blockers so the report explains B/C failures honestly. */
function detectLimitation(...results: Array<CodexCliResult | undefined>): string | undefined {
  const text = results.filter(Boolean).map((r) => `${r!.stdout}\n${r!.stderr}`).join("\n");
  if (/usage limit|purchase more credits|insufficient_quota|quota/i.test(text)) {
    return "Codex CLI launched and accepted the prompt, but the backing account hit its usage limit / quota. This is an account limitation, not a RiskRadar or CLI defect. Retry after the limit resets or top up credits.";
  }
  if (/not logged in|unauthorized|authentication|please run .*login/i.test(text)) {
    return "Codex CLI launched but is not authenticated. Run the Codex login flow, then re-run verify:codex-cli.";
  }
  return undefined;
}

function summarize(result: CodexCliResult) {
  return {
    command: result.command,
    args: result.args,
    exitCode: result.status,
    timedOut: result.timedOut,
    durationMs: result.durationMs,
    stdout: result.stdout.slice(0, 2000),
    stderr: result.stderr.slice(0, 1200)
  };
}

function disposableWorkspace(label: string): string {
  const dir = path.join(os.tmpdir(), `riskradar-codex-cli-${label}-${Date.now()}`);
  mkdirSync(dir, { recursive: true });
  return dir;
}

function cleanup(dir: string): void {
  if (process.env.RISKRADAR_RETAIN_WORKSPACES === "true") return;
  rmSync(dir, { recursive: true, force: true });
}

async function main() {
  const status = codexStatus();
  if (!status.configured) {
    // Honest report: Codex cannot run, so the live remediation cannot either.
    console.log(safeJson({
      ok: false,
      codexAvailable: false,
      codexMessage: status.message,
      checks: { version: null, execHelp: null, noRepoJson: null, fileEdit: null },
      recommendation: "Install/authenticate the Codex CLI or set CODEX_BIN before running verify:codex-live."
    }));
    process.exit(1);
  }

  // Check A: version + exec help. Confirms the CLI is reachable and exposes
  // enforceable sandbox flags.
  const version = await codexVersion();
  const execHelp = await codexExecHelp();
  const sandboxFlagPresent = execHelp.stdout.includes("--sandbox") || execHelp.stderr.includes("--sandbox");

  // Check B: tiny no-repo prompt asking for a short JSON object only.
  let noRepo: CodexCliResult | undefined;
  let jsonDetected = false;
  const noRepoWorkspace = disposableWorkspace("norepo");
  try {
    noRepo = await runCodexPrompt(noRepoWorkspace, NO_REPO_PROMPT, { timeoutMs: DIAGNOSTIC_TIMEOUT_MS });
    jsonDetected = noRepo.stdout.includes('"riskradar codex check"');
  } catch (error) {
    noRepo = undefined;
    console.error(safeJson({ checkB: "error", message: error instanceof Error ? error.message : String(error) }));
  } finally {
    cleanup(noRepoWorkspace);
  }

  // Check C: tiny single-file edit in a disposable workspace (before -> after).
  let fileEdit: CodexCliResult | undefined;
  let fileChanged = false;
  let finalContents: string | undefined;
  const editWorkspace = disposableWorkspace("edit");
  const editTarget = path.join(editWorkspace, "codex-check.txt");
  try {
    writeFileSync(editTarget, "before\n");
    fileEdit = await runCodexPrompt(editWorkspace, FILE_EDIT_PROMPT, { timeoutMs: DIAGNOSTIC_TIMEOUT_MS });
    finalContents = existsSync(editTarget) ? readFileSync(editTarget, "utf8").trim() : undefined;
    fileChanged = finalContents === "after";
  } catch (error) {
    fileEdit = undefined;
    console.error(safeJson({ checkC: "error", message: error instanceof Error ? error.message : String(error) }));
  } finally {
    cleanup(editWorkspace);
  }

  // The diagnostic passes when the CLI itself is healthy. The per-task results
  // (jsonDetected, fileChanged) are reported so the operator can judge whether
  // a live remediation will complete, without faking success.
  const ok = version.ok && execHelp.ok && sandboxFlagPresent;
  const limitation = detectLimitation(noRepo, fileEdit);

  console.log(safeJson({
    ok,
    codexAvailable: true,
    codexMessage: status.message,
    cliHealthy: ok,
    noRepoJsonWorked: jsonDetected,
    fileEditWorked: fileChanged,
    limitation,
    diagnosticTimeoutMs: DIAGNOSTIC_TIMEOUT_MS,
    sandboxFlagPresent,
    scopedPromptPreview: buildScopedCodexPrompt({ packageName: "lodash", currentVersion: "4.17.20", fixedVersion: "4.17.21" }),
    checks: {
      version: summarize(version),
      execHelp: { ...summarize(execHelp), stdout: execHelp.stdout.slice(0, 400) },
      noRepoJson: noRepo ? { ...summarize(noRepo), jsonDetected } : { ran: false, jsonDetected },
      fileEdit: fileEdit ? { ...summarize(fileEdit), fileChanged, finalContents } : { ran: false, fileChanged }
    }
  }));

  if (!ok) process.exit(1);
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
