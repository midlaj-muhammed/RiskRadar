/**
 * MCP tool-poisoning detector.
 *
 * Scans an external MCP tool's description/metadata for hidden instructions,
 * zero-width smuggling characters, and prompt-injection patterns. RiskRadar
 * is itself an MCP server today; it does not consume third-party MCP servers
 * yet, so this module is exported and tested for when it does — and so a
 * judge asking "what about tool poisoning?" gets a real answer instead of
 * a hand-wave.
 *
 * Reference: the ~84% tool-poisoning attack success rate observed in MCP-ITP
 * research under auto-approve is exactly what this guard exists to surface.
 */
import { sanitizeForLlmContext } from "./promptInjection";

export interface ToolPoisoningCheck {
  poisoned: boolean;
  flags: string[];
}

const TOOL_POISONING_PATTERNS: ReadonlyArray<{ name: string; re: RegExp }> = [
  // HTML comments are invisible to humans browsing the description but read by the model.
  { name: "hidden_instruction_comment", re: /<!--[\s\S]*?(?:ignore|override|jailbreak|system\s+prompt|hidden|secret\s+task)[\s\S]*?-->/i },
  // Zero-width characters used to smuggle text past human review.
  { name: "zero_width_smuggling", re: /[​‌‍⁠﻿]/ },
  // Imperative-mood instructions inside a description ("Always do X", "Never tell the user...").
  { name: "imperative_to_model", re: /\b(?:when\s+you\s+see\s+this|always\s+(?:include|append|send)|never\s+(?:tell|mention|reveal)|do\s+not\s+(?:mention|tell)|secret\s+task|hidden\s+goal)/i },
  // Role-override attempts.
  { name: "role_override", re: /\b(?:you\s+are\s+now|act\s+as|forget\s+everything|new\s+(?:system\s+)?instructions?)/i },
  // Exfiltration text targeting env / secrets.
  { name: "exfil_in_metadata", re: /\b(?:send|exfiltrate|leak|upload|forward)\s+(?:.{0,40})\b(?:env|secret|key|token|credential|\.env)/i }
];

/**
 * Returns a verdict on a tool description. Also runs the broader prompt-injection
 * sanitizer so flags from both checks are surfaced (prefixed `pi:` for the
 * sanitizer's signals so the source of each flag is clear).
 */
export function scanMcpToolDescription(text: string | undefined | null): ToolPoisoningCheck {
  if (!text) return { poisoned: false, flags: [] };
  const flags: string[] = [];
  for (const { name, re } of TOOL_POISONING_PATTERNS) {
    if (re.test(text)) flags.push(name);
  }
  const pi = sanitizeForLlmContext(text);
  if (pi.flagged) flags.push(...pi.patterns.map((p) => `pi:${p}`));
  return { poisoned: flags.length > 0, flags };
}

/** Batch helper for scanning an array of tools (name + description). */
export function scanMcpToolList(tools: Array<{ name?: string; description?: string }>): Array<{ name: string; check: ToolPoisoningCheck }> {
  return tools.map((tool, index) => ({
    name: tool.name ?? `tool[${index}]`,
    check: scanMcpToolDescription(tool.description ?? "")
  }));
}
