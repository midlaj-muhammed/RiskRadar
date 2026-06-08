import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

/**
 * Reachability / VEX-lite triage.
 *
 * A CVE in a dependency only matters if the vulnerable package is actually used.
 * This is a lightweight, HONEST first-party import signal — not full call-graph
 * analysis. It answers "is this package imported anywhere in the project's own
 * source?" to triage noise, in the spirit of VEX (Vulnerability Exploitability
 * eXchange). It is intentionally conservative:
 *  - direct dep imported in source  -> "imported" (treat as reachable)
 *  - direct npm dep NOT imported     -> "not_imported" (likely dev/unused → de-prioritize)
 *  - transitive dep                  -> "indirect" (reached via a parent; can't be first-party-imported)
 *  - python dep not found            -> "unknown" (PyPI name often differs from the import name)
 */
export type ReachabilitySignal = "imported" | "not_imported" | "indirect" | "unknown";

export interface ReachabilityResult {
  status: ReachabilitySignal;
  note: string;
}

const NPM_SOURCE = /\.(js|jsx|ts|tsx|mjs|cjs)$/i;
const PY_SOURCE = /\.py$/i;
const SKIP_DIRS = new Set(["node_modules", ".git", ".next", "dist", "build", ".turbo", "vendor", ".venv", "venv", "__pycache__", ".tools"]);

function walk(root: string, visit: (filePath: string) => void, depth = 0): void {
  if (depth > 12 || !existsSync(root)) return;
  for (const entry of readdirSync(root)) {
    if (SKIP_DIRS.has(entry)) continue;
    const full = path.join(root, entry);
    let stat;
    try { stat = statSync(full); } catch { continue; }
    if (stat.isDirectory()) walk(full, visit, depth + 1);
    else if (stat.isFile()) visit(full);
  }
}

/** Top-level package name from an npm specifier (handles scopes + subpaths). */
function npmTopLevel(specifier: string): string {
  if (specifier.startsWith("@")) return specifier.split("/").slice(0, 2).join("/");
  return specifier.split("/")[0] ?? specifier;
}

export interface FirstPartyImports {
  npm: Set<string>;
  python: Set<string>;
}

/** Scans first-party source ONCE, collecting imported top-level package names. */
export function collectFirstPartyImports(projectPath: string): FirstPartyImports {
  const npm = new Set<string>();
  const python = new Set<string>();
  walk(projectPath, (filePath) => {
    const base = path.basename(filePath);
    const isNpm = NPM_SOURCE.test(base);
    const isPy = PY_SOURCE.test(base);
    if (!isNpm && !isPy) return;
    let content = "";
    try { content = readFileSync(filePath, "utf8"); } catch { return; }
    if (content.length > 2_000_000) return;
    if (isNpm) {
      for (const match of content.matchAll(/(?:require\(|import\s*\(|from)\s*['"]([^'"]+)['"]/g)) {
        const spec = match[1];
        if (spec && !spec.startsWith(".") && !spec.startsWith("node:")) npm.add(npmTopLevel(spec));
      }
      for (const match of content.matchAll(/import\s+['"]([^'"]+)['"]/g)) {
        const spec = match[1];
        if (spec && !spec.startsWith(".") && !spec.startsWith("node:")) npm.add(npmTopLevel(spec));
      }
    } else {
      for (const match of content.matchAll(/^\s*(?:from\s+([A-Za-z0-9_]+)|import\s+([A-Za-z0-9_]+))/gm)) {
        const mod = match[1] ?? match[2];
        if (mod) python.add(mod.toLowerCase());
      }
    }
  });
  return { npm, python };
}

function normalizePy(name: string): string {
  return name.toLowerCase().replace(/[-.]+/g, "_");
}

/** Computes the reachability signal for a finding given the collected imports. */
export function reachabilityForFinding(
  finding: { packageName: string; ecosystem: string; dependencyType: "direct" | "transitive" | "unknown" },
  imports: FirstPartyImports
): ReachabilityResult {
  if (finding.dependencyType === "transitive") {
    return { status: "indirect", note: "Transitive dependency — reached via a parent package, not a first-party import." };
  }
  const eco = finding.ecosystem.toLowerCase();
  if (eco === "npm") {
    return imports.npm.has(finding.packageName)
      ? { status: "imported", note: "Imported in first-party source — treat as reachable." }
      : { status: "not_imported", note: "Not imported in first-party source — likely unused/dev-only; de-prioritize (VEX-lite)." };
  }
  if (eco === "pypi" || eco === "pip" || eco === "python") {
    const norm = normalizePy(finding.packageName);
    const hit = [...imports.python].some((mod) => normalizePy(mod) === norm || norm.startsWith(normalizePy(mod)) || normalizePy(mod).startsWith(norm));
    return hit
      ? { status: "imported", note: "Imported in first-party source — treat as reachable." }
      : { status: "unknown", note: "Not found by import name — PyPI package names often differ from import names, so reachability is unknown." };
  }
  return { status: "unknown", note: "Reachability not analyzed for this ecosystem." };
}
