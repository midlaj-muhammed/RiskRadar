/**
 * Prompt-injection input sanitization.
 *
 * First-line defense against adversarial text in attacker-controllable inputs
 * (CVE descriptions, package READMEs, scanner output) before it reaches an
 * LLM context. NOT a substitute for the rest of the defense-in-depth:
 *
 *  - Codex runs in a workspace-write sandbox (blast radius is limited).
 *  - Non-Codex models can only return strict-JSON plans, never edit the repo.
 *  - All consequential actions require a signed Telegram approval.
 *
 * This module strips known injection markers and bounds the input length so a
 * single CVE description cannot blow past the model context window or smuggle
 * instructions disguised as advisory text.
 */
export interface SanitizedText {
  sanitized: string;
  flagged: boolean;
  patterns: string[];
}

const INJECTION_PATTERNS: ReadonlyArray<{ name: string; re: RegExp }> = [
  { name: "instruction_override", re: /\b(ignore|disregard|forget)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|prompts?|context|rules?)/gi },
  { name: "system_persona", re: /\b(you\s+are\s+now|act\s+as|new\s+system\s+prompt|new\s+instructions?\s*:|system\s*prompt\s*:)/gi },
  { name: "role_marker", re: /\<\|(?:im_start|im_end|system|user|assistant|tool)\|\>|\[\/?(?:INST|SYSTEM)\]/gi },
  { name: "tool_invocation", re: /\b(use_tool|tool_call|<tool[\s>]|call_tool\(|invoke_function|execute_command)/gi },
  { name: "exfiltration_command", re: /\b(curl\s+(?:https?|ftp|file)|wget\s+\S+|\bnc\s+-|fetch\s*\(\s*['"]https?:|base64\s+-d\s+|powershell\s+-(?:Enc|Command)|cmd\.exe\s+\/c)/gi },
  { name: "data_exfil_hint", re: /\b(?:exfiltrat\w*|leak\w*|smuggle|steal)\b|\b(?:send|upload|forward|email)\b[^.\n]{0,40}\b(file|contents?|tokens?|secrets?|keys?|credentials?|env(?:ironment)?|\.env|\.aws|\.ssh|password|cookies?|sessions?|api[_\s-]?key)\b/gi },
  { name: "code_injection_marker", re: /<!--\s*(prompt|injection|override|jailbreak|do\s+not\s+show)/gi },
  { name: "zero_width", re: /[​‌‍⁠﻿]/g }
];

const DEFAULT_MAX = 4000;

/**
 * Strips known prompt-injection markers and bounds the length. Returns the
 * cleaned text plus an honest flag listing what was stripped so the caller
 * can log it in an audit receipt and decide whether to refuse the input.
 */
export function sanitizeForLlmContext(input: string | undefined | null, options: { maxLength?: number } = {}): SanitizedText {
  if (!input) return { sanitized: "", flagged: false, patterns: [] };
  let text = String(input);
  const flagged: string[] = [];
  for (const { name, re } of INJECTION_PATTERNS) {
    if (re.test(text)) {
      flagged.push(name);
      text = text.replace(re, "[redacted]");
    }
  }
  const max = options.maxLength ?? DEFAULT_MAX;
  if (text.length > max) text = text.slice(0, max) + "…[truncated]";
  return { sanitized: text, flagged: flagged.length > 0, patterns: flagged };
}
