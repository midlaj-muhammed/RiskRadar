import { getEnv } from "./env";
import { redact } from "./redaction";

/**
 * Deployment / Vercel preview verification. Pings a deployment URL and reports
 * whether it is live (no deploy is triggered). Used to confirm a project's
 * deployment URL responds before/after remediation.
 */
export interface DeploymentCheck {
  url: string;
  reachable: boolean;
  status?: number;
  ok: boolean;
  vercel: boolean;
  latencyMs?: number;
  error?: string;
}

/** Pure classifier (testable without network). */
export function classifyDeploymentResponse(status: number, headers: { get(name: string): string | null }): { ok: boolean; vercel: boolean } {
  const vercel = Boolean(headers.get("x-vercel-id") || headers.get("server")?.toLowerCase().includes("vercel"));
  return { ok: status >= 200 && status < 400, vercel };
}

export async function verifyDeploymentUrl(url: string, options: { timeoutMs?: number } = {}): Promise<DeploymentCheck> {
  const timeoutMs = options.timeoutMs ?? Number(getEnv("RISKRADAR_DEPLOYMENT_TIMEOUT_MS") ?? 8000);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const started = Date.now();
  try {
    const response = await fetch(url, { method: "GET", redirect: "follow", signal: controller.signal });
    const { ok, vercel } = classifyDeploymentResponse(response.status, response.headers);
    return { url, reachable: true, status: response.status, ok, vercel, latencyMs: Date.now() - started };
  } catch (error) {
    const aborted = error instanceof Error && error.name === "AbortError";
    return { url, reachable: false, ok: false, vercel: false, error: aborted ? `timed out after ${timeoutMs}ms` : redact(error instanceof Error ? error.message : String(error)) };
  } finally {
    clearTimeout(timer);
  }
}
