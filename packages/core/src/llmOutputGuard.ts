/**
 * LLM output classifier.
 *
 * Inspects model responses BEFORE RiskRadar consumes the plan or summary, so
 * jailbreak signatures, embedded shell-exfiltration commands, and obvious
 * secret-dump attempts are caught and the response can be rejected. Returns
 * "suspicious" plus a list of reasons; the caller decides the policy
 * (reject, retry, log only).
 */
export interface OutputClassification {
  suspicious: boolean;
  reasons: string[];
}

const SUSPICIOUS_PATTERNS: ReadonlyArray<{ name: string; re: RegExp }> = [
  { name: "shell_pipe_exec", re: /\b(?:curl|wget)\b[^\n]{0,200}\|\s*(?:sh|bash|zsh|node|python(?:3)?|powershell)\b/i },
  { name: "remote_fetch", re: /\b(?:curl|wget)\s+(?:-[A-Za-z]+\s+)*['"]?https?:\/\/[^\s'"]+/i },
  { name: "base64_decode_exec", re: /\bbase64\s+-d\b[^\n]{0,80}\|\s*(?:sh|bash|node|python)/i },
  { name: "secret_dump_cat", re: /\b(?:cat|type|Get-Content)\b\s+[~./][^\n]{0,80}(?:\.env|\.aws\b|\.ssh\/|\.gnupg|\.netrc|credentials)/i },
  { name: "env_var_dump", re: /\b(?:printenv\b|env\s*\||echo\s+\$[A-Z_]*(?:TOKEN|KEY|SECRET|PASSWORD|API))/i },
  { name: "remote_eval", re: /\b(?:eval|exec)\s*\(\s*(?:require\s*\(\s*['"]https?:|fetch\s*\(\s*['"]https?:)/i },
  { name: "jailbreak_marker", re: /\b(?:DAN\s+mode|developer\s+mode\s+activated|jailbroken|i\s+am\s+(?:now\s+)?free\s+of\s+all\s+(?:rules|restrictions|filters)|ignore\s+(?:openai|anthropic)\s+policy)/i },
  { name: "tool_hijack", re: /<tool[^>]*>[\s\S]{0,400}<\/tool>|\bcall_tool\(/i },
  { name: "instruction_leak_attempt", re: /\b(reveal|print|show|disclose)\s+(?:the\s+)?(?:system\s+prompt|hidden\s+instructions?|original\s+prompt)/i },
  { name: "policy_bypass_marker", re: /\b(developer\s+override|admin\s+mode|root\s+access\s+granted|safety\s+(?:disabled|off))/i }
];

/** Classifies an LLM response. Empty inputs are not suspicious. */
export function classifyLlmOutput(text: string | undefined | null): OutputClassification {
  if (!text) return { suspicious: false, reasons: [] };
  const reasons: string[] = [];
  for (const { name, re } of SUSPICIOUS_PATTERNS) {
    if (re.test(text)) reasons.push(name);
  }
  return { suspicious: reasons.length > 0, reasons };
}
