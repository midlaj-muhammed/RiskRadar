import OpenAI from "openai";
import { getEnv } from "./env";
import { RiskRadarError } from "./errors";
import { CODEX_REMEDIATION_PROMPT } from "./codex";

export type AgentAdapterStatus = "configured" | "not_configured" | "unavailable";

export interface AgentAdapterInfo {
  id: "codex-cli" | "openai-sdk" | "vercel-ai-sdk" | "deterministic-npm" | "manual";
  label: string;
  status: AgentAdapterStatus;
  message: string;
  canModifyWorkspace: boolean;
}

export function listAgentAdapters(): AgentAdapterInfo[] {
  return [
    {
      id: "codex-cli",
      label: "Codex CLI",
      status: getEnv("CODEX_ENABLED") === "false" ? "not_configured" : "configured",
      message: "Uses authenticated Codex CLI/subscription flow where available; only adapter allowed to edit workspaces directly.",
      canModifyWorkspace: true
    },
    {
      id: "openai-sdk",
      label: "OpenAI SDK",
      status: getEnv("OPENAI_API_KEY") ? "configured" : "not_configured",
      message: getEnv("OPENAI_API_KEY") ? "Uses official OpenAI SDK Responses API for remediation plans." : "Set OPENAI_API_KEY to use the OpenAI SDK plan adapter.",
      canModifyWorkspace: false
    },
    {
      id: "vercel-ai-sdk",
      label: "Vercel AI SDK / AI Gateway",
      status: getEnv("AI_GATEWAY_API_KEY") || getEnv("VERCEL_OIDC_TOKEN") ? "configured" : "not_configured",
      message: getEnv("AI_GATEWAY_API_KEY") || getEnv("VERCEL_OIDC_TOKEN")
        ? "Uses AI SDK provider/model strings through Vercel AI Gateway."
        : "Set AI_GATEWAY_API_KEY or VERCEL_OIDC_TOKEN to use AI Gateway without provider-specific keys.",
      canModifyWorkspace: false
    },
    {
      id: "deterministic-npm",
      label: "Deterministic npm fixer",
      status: "configured",
      message: "Updates direct npm dependencies to known fixed versions and validates in a disposable workspace.",
      canModifyWorkspace: true
    },
    {
      id: "manual",
      label: "Manual remediation",
      status: "configured",
      message: "Always available; creates a human-readable remediation plan only.",
      canModifyWorkspace: false
    }
  ];
}

export async function createOpenAiRemediationPlan(context: unknown): Promise<string> {
  if (!getEnv("OPENAI_API_KEY")) {
    throw new RiskRadarError("openai_sdk_not_configured", "Set OPENAI_API_KEY to use the OpenAI SDK adapter.", { requiredEnv: "OPENAI_API_KEY" });
  }
  const client = new OpenAI({ apiKey: getEnv("OPENAI_API_KEY") });
  const response = await client.responses.create({
    model: getEnv("OPENAI_MODEL") ?? "gpt-5",
    input: `${CODEX_REMEDIATION_PROMPT}\n\nReturn a remediation plan only. Do not claim files were edited.\n\nContext:\n${JSON.stringify(context, null, 2)}`
  });
  return response.output_text;
}

export async function createVercelAiRemediationPlan(context: unknown): Promise<string> {
  if (!getEnv("AI_GATEWAY_API_KEY") && !getEnv("VERCEL_OIDC_TOKEN")) {
    throw new RiskRadarError("ai_gateway_not_configured", "Set AI_GATEWAY_API_KEY or VERCEL_OIDC_TOKEN to use the Vercel AI SDK adapter.", {
      requiredEnv: ["AI_GATEWAY_API_KEY", "VERCEL_OIDC_TOKEN"]
    });
  }
  const ai = await import("ai");
  const result = await ai.generateText({
    model: getEnv("AI_GATEWAY_MODEL") ?? "openai/gpt-5",
    prompt: `${CODEX_REMEDIATION_PROMPT}\n\nReturn a remediation plan only. Do not claim files were edited.\n\nContext:\n${JSON.stringify(context, null, 2)}`
  });
  return result.text;
}
