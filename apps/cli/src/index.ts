#!/usr/bin/env node
/**
 * RiskRadar CLI — a thin, standalone scanner over @riskradar/core.
 *
 *   riskradar scan [path]     Scan a project folder for vulnerable deps (npm + PyPI)
 *   riskradar --help
 *
 * It queries the live OSV database and tags each finding with the reachability
 * (VEX-lite) signal — so you fix what's actually imported first. Real results
 * only; with no network it simply reports no findings.
 */
import path from "node:path";
import { detectManifests } from "@riskradar/core";
import { queryOsvFindings } from "@riskradar/core";
import { collectFirstPartyImports, reachabilityForFinding } from "@riskradar/core";

const C = {
  reset: "\x1b[0m", dim: "\x1b[2m", bold: "\x1b[1m",
  orange: "\x1b[38;5;208m", red: "\x1b[31m", yellow: "\x1b[33m", green: "\x1b[32m", gray: "\x1b[90m"
};
const useColor = process.stdout.isTTY && process.env.NO_COLOR === undefined;
const c = (code: string, s: string) => (useColor ? code + s + C.reset : s);

const REACH_LABEL: Record<string, string> = {
  imported: "reachable", not_imported: "likely unused", indirect: "transitive", unknown: "unknown"
};
const SEVERITY_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0, "": 0 };
const SHORT_SEV: Record<string, string> = { critical: "CRIT", high: "HIGH", medium: "MED", low: "LOW", unknown: "—" };

function usage(): void {
  console.log(`
${c(C.orange, "●")} ${c(C.bold, "RiskRadar CLI")} — supply-chain scanner (npm + PyPI)

${c(C.bold, "Usage")}
  riskradar scan [path]        Scan a project folder (default: current directory)
  riskradar --help             Show this help

${c(C.bold, "Options")}
  --json                        Output findings as JSON
  --fail-on <level>             Exit non-zero if a finding at/above this severity exists
                                (critical | high | medium | low). Default: never fail.

${c(C.bold, "Examples")}
  npx riskradar-cli scan
  npx riskradar-cli scan ./my-app --fail-on high
  riskradar scan . --json > findings.json

Reachability: ${c(C.orange, "● reachable")} = imported in your source · ${c(C.gray, "○ likely unused / transitive")} = de-prioritized.
Queries the live OSV database; with no network it reports no findings.
`);
}

function sevColor(sev: string): string {
  if (sev === "critical" || sev === "high") return C.red;
  if (sev === "medium") return C.yellow;
  if (sev === "low") return C.gray;
  return C.gray;
}

/** Best-effort: fetch full OSV records to fill in severity the batch query omits. */
async function enrichSeverities(ids: string[]): Promise<Map<string, string>> {
  const out = new Map<string, string>();
  const unique = [...new Set(ids.filter(Boolean))];
  const limit = 8;
  let i = 0;
  async function worker(): Promise<void> {
    while (i < unique.length) {
      const id = unique[i++]!;
      try {
        const ctrl = new AbortController();
        const timer = setTimeout(() => ctrl.abort(), 5000);
        const res = await fetch(`https://api.osv.dev/v1/vulns/${encodeURIComponent(id)}`, { signal: ctrl.signal });
        clearTimeout(timer);
        if (!res.ok) continue;
        const body: any = await res.json();
        out.set(id, severityFromOsv(body));
      } catch { /* offline / rate-limited → leave unknown */ }
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, unique.length) }, worker));
  return out;
}

function severityFromOsv(vuln: any): string {
  const cvss = (vuln?.severity ?? []).find((s: any) => String(s.type).toUpperCase().startsWith("CVSS"));
  const m = cvss?.score?.match(/^(\d+(\.\d+)?)/);
  if (m) return labelForCvss(Number(m[1]));
  const ds = vuln?.database_specific?.severity;
  if (typeof ds === "string") {
    const l = ds.toLowerCase();
    if (["critical", "high", "medium", "moderate", "low"].includes(l)) return l === "moderate" ? "medium" : l;
  }
  return "unknown";
}
function labelForCvss(s: number): string {
  if (s >= 9) return "critical"; if (s >= 7) return "high"; if (s >= 4) return "medium"; if (s > 0) return "low"; return "unknown";
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) { usage(); process.exit(0); }
  if (argv[0] !== "scan") { console.error(c(C.red, `Unknown command: ${argv[0]}`)); usage(); process.exit(2); }

  const json = argv.includes("--json");
  const failOnIdx = argv.indexOf("--fail-on");
  const failOn = failOnIdx >= 0 ? (argv[failOnIdx + 1] ?? "").toLowerCase() : "";
  const positional = argv.slice(1).filter((a) => !a.startsWith("--") && a !== failOn);
  const target = path.resolve(positional[0] ?? process.cwd());

  if (!json) {
    console.error("");
    console.error(c(C.dim, `  $ riskradar scan ${positional[0] ?? "."}`));
    console.error(c(C.dim, `  Scanning ${target} via OSV…`));
  }

  const manifests = detectManifests(target);
  if (manifests.length === 0) {
    const msg = "No package.json or requirements.txt found. RiskRadar scans Node.js (npm) and Python (PyPI) projects.";
    if (json) console.log(JSON.stringify({ error: "unsupported_project", message: msg }, null, 2));
    else console.error(c(C.red, "  " + msg));
    process.exit(2);
  }

  const result = await queryOsvFindings(target, manifests);
  const imports = collectFirstPartyImports(target);

  let findings = result.findings.map((f) => {
    const reach = reachabilityForFinding(
      { packageName: f.packageName, ecosystem: f.ecosystem, dependencyType: f.dependencyType }, imports
    );
    const advisory = f.vulnerability.osvId ?? f.vulnerability.cveIds[0] ?? f.vulnerability.id;
    return {
      package: f.packageName, ecosystem: f.ecosystem, currentVersion: f.currentVersion,
      fixedVersion: f.fixedVersion ?? null,
      severity: (f.vulnerability.severity || "unknown").toLowerCase(),
      advisory, dependencyType: f.dependencyType,
      reachability: reach.status, reachabilityNote: reach.note
    };
  });

  // Fill missing severities from the OSV vuln records (batch query omits them).
  if (findings.some((f) => f.severity === "unknown" || !SEVERITY_RANK[f.severity])) {
    const enriched = await enrichSeverities(findings.map((f) => f.advisory));
    findings = findings.map((f) => (f.severity === "unknown" && enriched.has(f.advisory))
      ? { ...f, severity: enriched.get(f.advisory)! } : f);
  }

  // Reachable first, then by severity, then package name.
  findings.sort((a, b) => {
    const ra = a.reachability === "imported" ? 1 : 0, rb = b.reachability === "imported" ? 1 : 0;
    if (ra !== rb) return rb - ra;
    const sd = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    if (sd !== 0) return sd;
    return a.package.localeCompare(b.package);
  });

  if (json) {
    console.log(JSON.stringify({ target, scanner: result.scanner, count: findings.length, findings }, null, 2));
  } else {
    const groups = groupByPackage(findings);
    await resolveRealFixes(groups);
    printReport(groups, findings.length, result.scanner);
  }

  if (failOn && SEVERITY_RANK[failOn] !== undefined) {
    const breach = findings.some((f) => (SEVERITY_RANK[f.severity] ?? 0) >= SEVERITY_RANK[failOn]!);
    if (breach) process.exit(1);
  }
  process.exit(0);
}

/** Picks the higher of two semver-ish version strings. */
function maxVersion(a: string | null, b: string | null): string | null {
  if (!a) return b; if (!b) return a;
  const pa = a.split(".").map((n) => parseInt(n, 10));
  const pb = b.split(".").map((n) => parseInt(n, 10));
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const x = pa[i] ?? 0, y = pb[i] ?? 0;
    if (x !== y) return x > y ? a : b;
  }
  return a;
}

interface Group {
  package: string; ecosystem: string; currentVersion: string; severity: string;
  fixedVersion: string | null; reachability: string; count: number;
}

const isStable = (v: string) => /^\d+\.\d+\.\d+$/.test(v);
function cmpVersion(a: string, b: string): number {
  const pa = a.split(".").map((n) => parseInt(n, 10)), pb = b.split(".").map((n) => parseInt(n, 10));
  for (let i = 0; i < 3; i++) { const x = pa[i] ?? 0, y = pb[i] ?? 0; if (x !== y) return x - y; }
  return 0;
}

/** Groups per-advisory findings into one row per package. */
function groupByPackage(findings: Array<Record<string, any>>): Group[] {
  const map = new Map<string, Group>();
  for (const f of findings) {
    const key = `${f.package}@${f.currentVersion}`;
    const g = map.get(key);
    if (!g) {
      map.set(key, { package: f.package, ecosystem: f.ecosystem, currentVersion: f.currentVersion, severity: f.severity,
        fixedVersion: f.fixedVersion, reachability: f.reachability, count: 1 });
    } else {
      if ((SEVERITY_RANK[f.severity] ?? 0) > (SEVERITY_RANK[g.severity] ?? 0)) g.severity = f.severity;
      g.fixedVersion = maxVersion(g.fixedVersion, f.fixedVersion);
      g.count += 1;
    }
  }
  return [...map.values()].sort((a, b) => {
    const r = (b.reachability === "imported" ? 1 : 0) - (a.reachability === "imported" ? 1 : 0);
    if (r) return r;
    const s = (SEVERITY_RANK[b.severity] ?? 0) - (SEVERITY_RANK[a.severity] ?? 0);
    return s || a.package.localeCompare(b.package);
  });
}

/**
 * OSV "fixed" bounds are sometimes synthetic (e.g. lodash 4.18.0, which was
 * never published). Resolve each group's fix to the lowest *real* published
 * stable version that is >= the OSV target, so the recommendation is installable.
 */
async function resolveRealFixes(groups: Group[]): Promise<void> {
  await Promise.all(groups.map(async (g) => {
    if (!g.fixedVersion) return;
    try {
      const versions = await registryVersions(g.package, g.ecosystem);
      if (!versions.length) return;
      const target = g.fixedVersion;
      const atOrAbove = versions.filter((v) => cmpVersion(v, target) >= 0).sort(cmpVersion);
      // Lowest real published version that clears all advisories; else the latest real version.
      g.fixedVersion = atOrAbove[0] ?? [...versions].sort(cmpVersion)[versions.length - 1] ?? target;
    } catch { /* offline → keep the OSV target */ }
  }));
}

async function registryVersions(pkg: string, ecosystem: string): Promise<string[]> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), 8000);
  try {
    if (/pypi|python|pip/i.test(ecosystem)) {
      const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(pkg)}/json`, { signal: ctrl.signal });
      if (!res.ok) return [];
      const body: any = await res.json();
      return Object.keys(body.releases ?? {}).filter(isStable);
    }
    // Abbreviated packument (~50x smaller than the full doc) so big packages
    // like lodash parse well within the timeout.
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(pkg).replace("%40", "@")}`, {
      signal: ctrl.signal,
      headers: { accept: "application/vnd.npm.install-v1+json" }
    });
    if (!res.ok) return [];
    const body: any = await res.json();
    return Object.keys(body.versions ?? {}).filter(isStable);
  } finally {
    clearTimeout(timer);
  }
}

function printReport(groups: Group[], advisoryCount: number, scanner: string): void {
  if (groups.length === 0) {
    console.log("\n" + c(C.green, "  ✓ No known vulnerable dependencies found.") + c(C.dim, `  (scanner: ${scanner})\n`));
    return;
  }
  console.log("");
  console.log("  " + c(C.bold, `${groups.length} vulnerable package${groups.length === 1 ? "" : "s"}`)
    + c(C.dim, `  ·  ${advisoryCount} advisories  ·  scanner: ${scanner}`));
  console.log("");
  for (const g of groups) {
    const sev = (SHORT_SEV[g.severity] ?? "·").padEnd(4);
    const pkg = c(C.bold, g.package) + c(C.dim, `@${g.currentVersion}`);
    const fix = g.fixedVersion ? c(C.green, `→ ${g.fixedVersion}`) : c(C.dim, "manual review");
    const adv = g.count > 1 ? c(C.dim, `  (${g.count} advisories)`) : "";
    console.log(`  ${c(sevColor(g.severity), sev)}  ${pkg}  ${fix}${adv}`);
    const dot = g.reachability === "imported" ? c(C.orange, "● reachable") : c(C.gray, `○ ${REACH_LABEL[g.reachability]}`);
    console.log(`        ${dot}`);
  }
  const reachable = groups.filter((g) => g.reachability === "imported").length;
  console.log("");
  console.log("  " + c(C.orange, "▸") + " " + c(C.bold, `${reachable} reachable`) + c(C.dim, ` · ${groups.length - reachable} de-prioritized`));
  console.log("  " + c(C.dim, "Fix the reachable ones first.") + "\n");
}

main().catch((err) => {
  console.error(c(C.red, "RiskRadar CLI error: ") + (err instanceof Error ? err.message : String(err)));
  process.exit(1);
});
