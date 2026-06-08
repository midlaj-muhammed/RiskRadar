import { existsSync, lstatSync, realpathSync } from "node:fs";
import path from "node:path";
import { RiskRadarError } from "./errors";

function normalizeForCompare(value: string): string {
  const resolved = path.resolve(value);
  return process.platform === "win32" ? resolved.toLowerCase() : resolved;
}

export function assertSafeLocalPath(requestedPath: string, allowlistRoots: string[]): string {
  if (!requestedPath || requestedPath.includes("\0")) {
    throw new RiskRadarError("local_path_invalid", "Local path is empty or invalid.");
  }
  if (allowlistRoots.length === 0) {
    throw new RiskRadarError("local_roots_not_configured", "Set RISKRADAR_LOCAL_ROOTS before adding local folders.", {
      requiredEnv: "RISKRADAR_LOCAL_ROOTS"
    });
  }
  if (!existsSync(requestedPath)) {
    throw new RiskRadarError("local_path_not_found", "The requested local path does not exist.", { requestedPath });
  }
  const realRequested = realpathSync(requestedPath);
  const normalizedRequested = normalizeForCompare(realRequested);
  const allowed = allowlistRoots.some((root) => {
    if (!existsSync(root)) return false;
    const realRoot = realpathSync(root);
    const parsed = path.parse(realRoot);
    if (normalizeForCompare(realRoot) === normalizeForCompare(parsed.root)) return false;
    const normalizedRoot = normalizeForCompare(realRoot);
    return normalizedRequested === normalizedRoot || normalizedRequested.startsWith(normalizedRoot + path.sep);
  });
  if (!allowed) {
    throw new RiskRadarError("local_path_not_allowlisted", "Local folder is outside RISKRADAR_LOCAL_ROOTS.", {
      requestedPath: realRequested,
      allowlistRoots
    });
  }
  const stat = lstatSync(realRequested);
  if (!stat.isDirectory()) {
    throw new RiskRadarError("local_path_not_directory", "Local project path must be a directory.", { requestedPath: realRequested });
  }
  return realRequested;
}
