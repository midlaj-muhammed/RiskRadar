import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { RiskRadarError } from "./errors";

const DEPENDENCY_SECTIONS = ["dependencies", "devDependencies", "optionalDependencies"] as const;

/**
 * Updates a single dependency version in package.json across the standard
 * dependency sections. Pure filesystem edit — never runs npm and never touches
 * any file other than the given manifest. Returns true when something changed.
 */
export function updateManifestDependencyVersion(manifestPath: string, packageName: string, version: string): boolean {
  if (!existsSync(manifestPath)) {
    throw new RiskRadarError("manifest_missing", "package.json is missing from the remediation workspace.", { manifestPath });
  }
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8")) as Record<string, Record<string, string> | unknown>;
  let updated = false;
  for (const section of DEPENDENCY_SECTIONS) {
    const deps = manifest[section];
    if (deps && typeof deps === "object" && packageName in (deps as Record<string, string>)) {
      (deps as Record<string, string>)[packageName] = version;
      updated = true;
    }
  }
  if (updated) writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return updated;
}

/**
 * Updates a dependency version in a Python requirements.txt. Handles `pkg==x`,
 * `pkg===x`, and `pkg>=x` style pins (case-insensitive name, PEP 503 normalized).
 * Pure filesystem edit. Returns true when a line changed.
 */
export function updateRequirementsVersion(requirementsPath: string, packageName: string, version: string): boolean {
  if (!existsSync(requirementsPath)) {
    throw new RiskRadarError("manifest_missing", "requirements.txt is missing from the remediation workspace.", { requirementsPath });
  }
  const normalize = (name: string) => name.toLowerCase().replace(/[-_.]+/g, "-");
  const target = normalize(packageName);
  let updated = false;
  const lines = readFileSync(requirementsPath, "utf8").split(/\r?\n/).map((line) => {
    const match = line.match(/^(\s*)([A-Za-z0-9._-]+)(\s*)(==|===|>=|~=)(\s*)([^\s#;]+)(.*)$/);
    if (!match) return line;
    const [, lead, name, sp1, op, sp2, , rest] = match;
    if (normalize(name!) !== target) return line;
    updated = true;
    // Pin exactly to the fixed version regardless of original operator.
    return `${lead}${name}${sp1}==${sp2}${version}${rest}`;
  });
  if (updated) writeFileSync(requirementsPath, lines.join("\n"));
  return updated;
}

export interface LockfilePackageDiff {
  packageName: string;
  before?: string;
  after?: string;
  changed: boolean;
}

/** Reads `<name> -> version` pairs from a package-lock.json string (v1/v2/v3). */
export function parseLockfilePackages(content: string): Map<string, string> {
  const versions = new Map<string, string>();
  let lock: { packages?: Record<string, { version?: string }>; dependencies?: Record<string, { version?: string }> };
  try {
    lock = JSON.parse(content);
  } catch {
    return versions;
  }
  // lockfileVersion 2/3 store an entry per install path keyed by "node_modules/<name>".
  for (const [key, value] of Object.entries(lock.packages ?? {})) {
    if (!key) continue;
    const marker = "node_modules/";
    const index = key.lastIndexOf(marker);
    if (index < 0) continue;
    const name = key.slice(index + marker.length);
    if (name && value?.version) versions.set(name, value.version);
  }
  // lockfileVersion 1 fallback.
  for (const [name, value] of Object.entries(lock.dependencies ?? {})) {
    if (name && value?.version && !versions.has(name)) versions.set(name, value.version);
  }
  return versions;
}

/**
 * Lightweight before/after diff for one package across two package-lock.json
 * snapshots — used to show that a remediation actually moved the vulnerable
 * version (e.g. lodash 4.17.20 -> 4.17.21).
 */
export function diffLockfilePackage(beforeLock: string, afterLock: string, packageName: string): LockfilePackageDiff {
  const before = parseLockfilePackages(beforeLock).get(packageName);
  const after = parseLockfilePackages(afterLock).get(packageName);
  return { packageName, before, after, changed: Boolean(after) && before !== after };
}
