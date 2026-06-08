import { mkdirSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";
import { id, now } from "./database";
import { logDir, getEnv } from "./env";
import { redact } from "./redaction";
import type { ValidationRun } from "./types";

export async function runCommand(command: string, cwd: string, remediationJobId: string, timeoutMs = Number(getEnv("RISKRADAR_COMMAND_TIMEOUT_MS") ?? 120000)): Promise<ValidationRun> {
  const started = Date.now();
  const logPath = path.join(logDir(), `${remediationJobId}-${Date.now()}.log`);
  mkdirSync(path.dirname(logPath), { recursive: true });
  return new Promise((resolve) => {
    const child = spawn(command, { cwd, shell: true, env: safeChildEnv() });
    let output = "";
    const timer = setTimeout(() => child.kill("SIGTERM"), timeoutMs);
    child.stdout.on("data", (chunk) => (output += chunk.toString()));
    child.stderr.on("data", (chunk) => (output += chunk.toString()));
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      const durationMs = Date.now() - started;
      writeFileSync(logPath, redact(output));
      resolve({
        id: id("val"),
        remediationJobId,
        command,
        status: signal ? "timeout" : code === 0 ? "passed" : "failed",
        exitCode: code ?? undefined,
        durationMs,
        logPath,
        createdAt: now()
      });
    });
  });
}

export function safeChildEnv(): NodeJS.ProcessEnv {
  return {
    PATH: process.env.PATH,
    Path: process.env.Path,
    HOME: process.env.HOME,
    USERPROFILE: process.env.USERPROFILE,
    NODE_ENV: process.env.NODE_ENV,
    CI: "1",
    npm_config_fund: "false",
    npm_config_audit: "false",
    npm_config_ignore_scripts: validationInstallScriptsAllowed() ? "false" : "true"
  } satisfies NodeJS.ProcessEnv;
}

export function validationInstallScriptsAllowed(): boolean {
  return getEnv("RISKRADAR_ALLOW_VALIDATION_SCRIPTS") === "true";
}

export function safeNpmInstallCommand(hasPackageLock: boolean): string {
  const base = hasPackageLock ? "npm ci" : "npm install";
  return validationInstallScriptsAllowed() ? base : `${base} --ignore-scripts`;
}
