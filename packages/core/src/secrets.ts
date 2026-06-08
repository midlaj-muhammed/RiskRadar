import { existsSync, readFileSync } from "node:fs";

/**
 * File-based secret-manager indirection. Instead of (or in addition to) .env,
 * secrets can be supplied via a JSON file pointed to by RISKRADAR_SECRETS_FILE --
 * which maps cleanly to a Docker/Kubernetes secret mount or a Vault file sink.
 * Only fills keys that are not already set (explicit env / .env win), so it never
 * clobbers operator-provided values. Returns the names loaded (never the values).
 */
export function loadSecretsFile(filePath = process.env.RISKRADAR_SECRETS_FILE): { loaded: number; keys: string[] } {
  if (!filePath || !existsSync(filePath)) return { loaded: 0, keys: [] };
  let data: Record<string, unknown>;
  try {
    data = JSON.parse(readFileSync(filePath, "utf8"));
  } catch {
    return { loaded: 0, keys: [] };
  }
  const keys: string[] = [];
  for (const [key, value] of Object.entries(data)) {
    if (typeof value === "string" && process.env[key] === undefined) {
      process.env[key] = value;
      keys.push(key);
    }
  }
  return { loaded: keys.length, keys };
}
