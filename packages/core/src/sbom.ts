import { spawnSync } from "node:child_process";
import { commandExists, getEnv } from "./env";
import { RiskRadarError } from "./errors";
import { redact } from "./redaction";

function syftBin(): string {
  return getEnv("SYFT_BIN") ?? getEnv("RISKRADAR_SCANNER_SYFT_PATH") ?? "syft";
}

export function sbomToolAvailable(): boolean {
  return commandExists(syftBin());
}

export function generateSbom(projectPath: string): { format: string; output: string } {
  const bin = syftBin();
  if (!commandExists(bin)) {
    throw new RiskRadarError("sbom_tool_missing", "SBOM generation requires Syft. Install syft or set SYFT_BIN.", { requiredTool: bin });
  }
  // No shell: absolute paths (which may contain spaces) are passed as argv.
  const result = spawnSync(bin, [projectPath, "-o", "cyclonedx-json", "-q"], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 });
  if (result.status !== 0) {
    throw new RiskRadarError("sbom_generation_failed", "Syft failed to generate an SBOM.", { stderr: redact(result.stderr) }, 502);
  }
  return { format: "cyclonedx-json", output: redact(result.stdout) };
}

/** Parses CycloneDX JSON into a name→version map. */
export function parseSbomComponents(cyclonedxJson: string): Map<string, string> {
  const map = new Map<string, string>();
  try {
    const doc = JSON.parse(cyclonedxJson) as { components?: Array<{ name?: string; version?: string }> };
    for (const component of doc.components ?? []) {
      if (component.name) map.set(component.name, component.version ?? "");
    }
  } catch {
    // not valid CycloneDX
  }
  return map;
}

export interface SbomDiff {
  beforeCount: number;
  afterCount: number;
  added: string[];
  removed: string[];
  changed: Array<{ name: string; before: string; after: string }>;
}

/** Before/after SBOM diff (added/removed/version-changed components). */
export function sbomDiff(beforeSbom: string, afterSbom: string): SbomDiff {
  const before = parseSbomComponents(beforeSbom);
  const after = parseSbomComponents(afterSbom);
  const added: string[] = [];
  const removed: string[] = [];
  const changed: Array<{ name: string; before: string; after: string }> = [];
  for (const [name, version] of after) {
    if (!before.has(name)) added.push(name);
    else if (before.get(name) !== version) changed.push({ name, before: before.get(name)!, after: version });
  }
  for (const name of before.keys()) if (!after.has(name)) removed.push(name);
  return { beforeCount: before.size, afterCount: after.size, added, removed, changed };
}
