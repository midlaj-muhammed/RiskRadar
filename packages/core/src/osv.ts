import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import semver from "semver";
import type { Vulnerability } from "./types";
import type { PackageManifest } from "./packageDetection";
import { getEnv } from "./env";
import { RiskRadarError } from "./errors";

export interface NormalizedOsvFinding {
  vulnerability: Vulnerability;
  packageName: string;
  ecosystem: string;
  currentVersion: string;
  fixedVersion?: string;
  affectedRanges: string[];
  dependencyType: "direct" | "transitive" | "unknown";
}

export interface OsvScanResult {
  findings: NormalizedOsvFinding[];
  scanner: "osv-scanner" | "osv-api";
  scanConfidence: "lockfile" | "direct_manifest_only";
}

interface OsvVulnerability {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  modified?: string;
  published?: string;
  references?: { url: string }[];
  affected?: Array<{
    package?: { name?: string; ecosystem?: string };
    ranges?: Array<{ type?: string; events?: Array<{ introduced?: string; fixed?: string }> }>;
    versions?: string[];
    ecosystem_specific?: Record<string, unknown>;
  }>;
  severity?: Array<{ type: string; score: string }>;
}

function osvScannerBin(): string {
  return getEnv("RISKRADAR_SCANNER_OSV_SCANNER_PATH") ?? "osv-scanner";
}

export function osvScannerAvailable(): boolean {
  if (getEnv("RISKRADAR_DISABLE_OSV_SCANNER") === "true") return false;
  const bin = osvScannerBin();
  if (bin.includes("\\") || bin.includes("/")) return existsSync(bin);
  const result = spawnSync(process.platform === "win32" ? "where.exe" : "command", process.platform === "win32" ? [bin] : ["-v", bin], {
    encoding: "utf8",
    shell: process.platform !== "win32"
  });
  return result.status === 0;
}

export async function queryOsvApi(manifest: PackageManifest): Promise<NormalizedOsvFinding[]> {
  const deps = { ...manifest.dependencies, ...manifest.devDependencies, ...manifest.optionalDependencies };
  const isNpm = manifest.ecosystem === "npm";
  const entries = Object.entries(deps).map(([name, rawVersion]) => [name, isNpm ? (semver.minVersion(rawVersion)?.version ?? rawVersion.replace(/^[^\d]*/, "")) : rawVersion.replace(/^[^\d=<>~!]*/, "")] as const);
  if (entries.length === 0) return [];
  const findings: NormalizedOsvFinding[] = [];
  for (let offset = 0; offset < entries.length; offset += 100) {
    const batch = entries.slice(offset, offset + 100);
    const response = await fetch(getEnv("OSV_API_URL") ?? "https://api.osv.dev/v1/querybatch", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        queries: batch.map(([name, version]) => ({
          version,
          package: { name, ecosystem: manifest.ecosystem }
        }))
      })
    });
    if (!response.ok) {
      throw new RiskRadarError("osv_api_failed", `OSV API returned ${response.status}.`, { status: response.status }, 502);
    }
    const body = (await response.json()) as { results?: Array<{ vulns?: OsvVulnerability[] }> };
    for (const [index, result] of (body.results ?? []).entries()) {
      const entry = batch[index];
      if (!entry) continue;
      const [name, version] = entry;
      for (const vuln of result.vulns ?? []) {
        const hydrated = await fetchOsvVulnerability(vuln.id).catch(() => vuln);
        findings.push(normalizeOsvVulnerability({ ...vuln, ...hydrated }, name, version, "direct", manifest.ecosystem));
      }
    }
  }
  return findings;
}

export async function queryOsvFindings(projectPath: string, manifests: PackageManifest[]): Promise<OsvScanResult> {
  const directNames = new Set(manifests.flatMap((manifest) => Object.keys({ ...manifest.dependencies, ...manifest.devDependencies, ...manifest.optionalDependencies })));
  const queryDirectManifests = async (): Promise<OsvScanResult> => {
    const apiFindings: NormalizedOsvFinding[] = [];
    for (const manifest of manifests) apiFindings.push(...await queryOsvApi(manifest));
    return { findings: apiFindings, scanner: "osv-api", scanConfidence: "direct_manifest_only" };
  };
  if (canRunOsvScanner(projectPath)) {
    const bin = osvScannerBin();
    const args = ["--format", "json", "--recursive", projectPath];
    const isCmd = process.platform === "win32" && /\.(cmd|bat)$/i.test(bin);
    const bare = !bin.includes("\\") && !bin.includes("/");
    const result = isCmd
      ? spawnSync(process.env.ComSpec ?? "cmd.exe", ["/d", "/c", bin, ...args], { encoding: "utf8", maxBuffer: 64 * 1024 * 1024 })
      : spawnSync(bin, args, { encoding: "utf8", shell: bare && process.platform === "win32", maxBuffer: 64 * 1024 * 1024 });
    if ((result.status ?? 1) !== 0 && !result.stdout) {
      if ((result.stderr ?? "").includes("No package sources found")) return await queryDirectManifests();
      throw new RiskRadarError("osv_scanner_failed", "OSV-Scanner failed before producing JSON output.", { stderr: result.stderr }, 502);
    }
    const findings = parseOsvScannerJson(result.stdout, directNames);
    return { findings, scanner: "osv-scanner", scanConfidence: "lockfile" };
  }
  return await queryDirectManifests();
}

export function parseOsvScannerJson(raw: string, directNames: Set<string>): NormalizedOsvFinding[] {
  const parsed = JSON.parse(raw) as {
    results?: Array<{
      packages?: Array<{
        package?: { name?: string; version?: string; ecosystem?: string };
        vulnerabilities?: OsvVulnerability[];
      }>;
    }>;
  };
  return (parsed.results ?? []).flatMap((result) =>
    (result.packages ?? []).flatMap((pkg) => {
      const packageName = pkg.package?.name;
      const version = pkg.package?.version;
      if (!packageName || !version) return [];
      const dependencyType = directNames.has(packageName) ? "direct" : "transitive";
      const ecosystem = pkg.package?.ecosystem ?? "npm";
      return (pkg.vulnerabilities ?? []).map((vulnerability) => normalizeOsvVulnerability(vulnerability, packageName, version, dependencyType, ecosystem));
    })
  );
}

async function fetchOsvVulnerability(id: string): Promise<OsvVulnerability> {
  const base = (getEnv("OSV_API_URL") ?? "https://api.osv.dev/v1/querybatch").replace(/\/querybatch$/, "");
  const response = await fetch(`${base}/vulns/${encodeURIComponent(id)}`);
  if (!response.ok) throw new RiskRadarError("osv_vulnerability_fetch_failed", `OSV vulnerability detail returned ${response.status}.`, { id, status: response.status }, 502);
  return await response.json() as OsvVulnerability;
}

export function normalizeOsvVulnerability(
  vuln: OsvVulnerability,
  packageName: string,
  currentVersion: string,
  dependencyType: "direct" | "transitive" | "unknown",
  ecosystem = "npm"
): NormalizedOsvFinding {
  const cveIds = (vuln.aliases ?? []).filter((alias) => alias.startsWith("CVE-"));
  const ghsaIds = [vuln.id, ...(vuln.aliases ?? [])].filter((alias) => alias.startsWith("GHSA-"));
  const fixedVersions = (vuln.affected ?? [])
    .flatMap((affected) => affected.ranges ?? [])
    .flatMap((range) => range.events ?? [])
    .map((event) => event.fixed)
    .filter((value): value is string => Boolean(value));
  const severity = parseSeverity(vuln);
  return {
    vulnerability: {
      id: vuln.id,
      source: "osv",
      osvId: vuln.id,
      cveIds,
      ghsaIds,
      summary: vuln.summary ?? vuln.id,
      details: vuln.details,
      severity: severity.label,
      cvssScore: severity.cvssScore,
      publishedAt: vuln.published,
      modifiedAt: vuln.modified,
      references: (vuln.references ?? []).map((reference) => reference.url)
    },
    packageName,
    ecosystem,
    currentVersion,
    // Non-npm ecosystems (e.g. PyPI) aren't semver — only sort when all are valid.
    fixedVersion: (fixedVersions.every((v) => semver.valid(v)) ? [...fixedVersions].sort(semver.compare) : fixedVersions)[0],
    affectedRanges: (vuln.affected ?? []).flatMap((affected) =>
      (affected.ranges ?? []).flatMap((range) => (range.events ?? []).map((event) => JSON.stringify(event)))
    ),
    dependencyType
  };
}

function parseSeverity(vuln: OsvVulnerability): { label: string; cvssScore?: number } {
  const cvss = (vuln.severity ?? []).find((item) => item.type.toUpperCase().startsWith("CVSS"));
  const scoreMatch = cvss?.score.match(/\/AV:|^(\d+(\.\d+)?)/);
  const directScore = scoreMatch?.[1] ? Number(scoreMatch[1]) : undefined;
  if (directScore) return { label: labelForCvss(directScore), cvssScore: directScore };
  return { label: "unknown" };
}

function labelForCvss(score: number): string {
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "medium";
  if (score > 0) return "low";
  return "unknown";
}

export function canRunOsvScanner(projectPath: string): boolean {
  return existsSync(projectPath) && osvScannerAvailable();
}
