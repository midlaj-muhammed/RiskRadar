const SECRET_PATTERNS = [
  /gh[pousr]_[A-Za-z0-9_]{20,}/g,
  /github_pat_[A-Za-z0-9_]{40,}/g,
  /sk-[A-Za-z0-9_-]{20,}/g,
  /\b\d{8,10}:[A-Za-z0-9_-]{30,}\b/g,
  /xox[baprs]-[A-Za-z0-9-]{20,}/g,
  /AKIA[0-9A-Z]{16}/g,
  /(?<=(token|secret|api[_-]?key|password|private[_-]?key)\s*[:=]\s*["']?)[^"'\s]{8,}/gi,
  /\b[A-Za-z0-9+/]{40,}={0,2}\b/g
];

export function redact(input: unknown): string {
  const text = typeof input === "string" ? input : JSON.stringify(input, null, 2);
  return SECRET_PATTERNS.reduce((current, pattern) => current.replace(pattern, "[REDACTED]"), text);
}

export function redactObject<T>(input: T): T {
  return JSON.parse(redact(input)) as T;
}
