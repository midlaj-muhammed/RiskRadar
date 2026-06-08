/**
 * Generates demo/seed.json — realistic, type-shaped state for the hosted Vercel
 * preview (RISKRADAR_DEMO=true). NO real scan data, no secrets. Lets judges
 * explore the dashboard UI without installing anything. Regenerate with:
 *   pnpm tsx scripts/make-demo-seed.ts
 */
import { mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { emptyState } from "../packages/core/src/database.ts";
import type { RiskRadarState } from "../packages/core/src/types.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const root = path.resolve(__dirname, "..");
const t = (daysAgo: number) => new Date(Date.now() - daysAgo * 86_400_000).toISOString();

const state: RiskRadarState = emptyState();

// ---- Projects ----
state.projects = [
  {
    id: "proj_web", name: "acme/web-storefront", sourceType: "github",
    githubOwner: "acme", githubRepo: "web-storefront", githubDefaultBranch: "main",
    repoUrl: "https://github.com/acme/web-storefront", isPathAllowlisted: false,
    packageManager: "npm", deploymentProvider: "vercel", deploymentUrl: "https://web-storefront.vercel.app",
    productionExposed: true, stack: ["next", "react", "node"], lastScanAt: t(0), lastScanStatus: "completed",
    createdAt: t(20), updatedAt: t(0)
  },
  {
    id: "proj_api", name: "acme/data-api (PyPI)", sourceType: "local",
    localPath: "/srv/acme/data-api", isPathAllowlisted: true,
    packageManager: "pip", deploymentProvider: "manual", productionExposed: true,
    stack: ["python", "flask"], lastScanAt: t(1), lastScanStatus: "completed",
    createdAt: t(18), updatedAt: t(1)
  }
];

// ---- Vulnerabilities ----
state.vulnerabilities = [
  { id: "vuln_lodash", source: "osv", osvId: "GHSA-jf85-cpcp-j695", cveIds: ["CVE-2019-10744"], ghsaIds: ["GHSA-jf85-cpcp-j695"],
    summary: "Prototype pollution in lodash via defaultsDeep allowing modification of Object.prototype.", severity: "high", cvssScore: 9.1,
    publishedAt: t(400), modifiedAt: t(120), references: ["https://github.com/lodash/lodash/pull/4336"] },
  { id: "vuln_axios", source: "osv", osvId: "GHSA-wf5p-g6vw-rhxx", cveIds: ["CVE-2023-45857"], ghsaIds: ["GHSA-wf5p-g6vw-rhxx"],
    summary: "axios SSRF / credential leakage when following cross-origin redirects with proxy configuration.", severity: "medium", cvssScore: 6.5,
    publishedAt: t(220), modifiedAt: t(80), references: ["https://github.com/axios/axios/security/advisories"] },
  { id: "vuln_minimist", source: "osv", osvId: "GHSA-xvch-5gv4-984h", cveIds: ["CVE-2021-44906"], ghsaIds: ["GHSA-xvch-5gv4-984h"],
    summary: "Prototype pollution in minimist (transitive). Reachable only via a parent CLI dependency.", severity: "medium", cvssScore: 5.6,
    publishedAt: t(300), modifiedAt: t(150), references: [] },
  { id: "vuln_requests", source: "osv", osvId: "GHSA-9wx4-h78v-vm56", cveIds: ["CVE-2023-32681"], ghsaIds: ["GHSA-9wx4-h78v-vm56"],
    summary: "Requests leaks Proxy-Authorization header on cross-origin redirects.", severity: "medium", cvssScore: 6.1,
    publishedAt: t(260), modifiedAt: t(90), references: ["https://github.com/psf/requests/security"] }
];

// ---- Findings (with reachability) ----
state.findings = [
  { id: "find_lodash", projectId: "proj_web", vulnerabilityId: "vuln_lodash", packageName: "lodash", ecosystem: "npm",
    currentVersion: "4.17.11", fixedVersion: "4.17.21", dependencyType: "direct", manifestPath: "package.json", lockfilePath: "package-lock.json",
    riskScore: 88, riskLevel: "critical", riskFactors: ["KEV-adjacent", "production exposed", "imported in source"], missingRiskData: [],
    fixStrategy: "safe_patch", status: "pr_ready", scanConfidence: "lockfile",
    reachability: "imported", reachabilityEvidence: "Imported in first-party source — treat as reachable.", createdAt: t(0), updatedAt: t(0) },
  { id: "find_axios", projectId: "proj_web", vulnerabilityId: "vuln_axios", packageName: "axios", ecosystem: "npm",
    currentVersion: "1.4.0", fixedVersion: "1.6.2", dependencyType: "direct", manifestPath: "package.json", lockfilePath: "package-lock.json",
    riskScore: 64, riskLevel: "high", riskFactors: ["production exposed", "imported in source"], missingRiskData: [],
    fixStrategy: "minor_upgrade", status: "fix_available", scanConfidence: "lockfile",
    reachability: "imported", reachabilityEvidence: "Imported in first-party source — treat as reachable.", createdAt: t(0), updatedAt: t(0) },
  { id: "find_minimist", projectId: "proj_web", vulnerabilityId: "vuln_minimist", packageName: "minimist", ecosystem: "npm",
    currentVersion: "1.2.5", fixedVersion: "1.2.8", dependencyType: "transitive", manifestPath: "package.json", lockfilePath: "package-lock.json",
    riskScore: 38, riskLevel: "medium", riskFactors: ["transitive only"], missingRiskData: [],
    fixStrategy: "safe_patch", status: "open", scanConfidence: "lockfile",
    reachability: "indirect", reachabilityEvidence: "Transitive dependency — reached via a parent package, not a first-party import.", createdAt: t(0), updatedAt: t(0) },
  { id: "find_chalkdev", projectId: "proj_web", vulnerabilityId: "vuln_minimist", packageName: "color-convert", ecosystem: "npm",
    currentVersion: "1.9.0", fixedVersion: "2.0.1", dependencyType: "direct", manifestPath: "package.json", lockfilePath: "package-lock.json",
    riskScore: 21, riskLevel: "low", riskFactors: ["dev dependency", "not imported"], missingRiskData: [],
    fixStrategy: "safe_patch", status: "open", scanConfidence: "lockfile",
    reachability: "not_imported", reachabilityEvidence: "Not imported in first-party source — likely unused/dev-only; de-prioritize (VEX-lite).", createdAt: t(0), updatedAt: t(0) },
  { id: "find_requests", projectId: "proj_api", vulnerabilityId: "vuln_requests", packageName: "requests", ecosystem: "PyPI",
    currentVersion: "2.28.0", fixedVersion: "2.31.0", dependencyType: "direct", manifestPath: "requirements.txt",
    riskScore: 59, riskLevel: "high", riskFactors: ["production exposed"], missingRiskData: [],
    fixStrategy: "minor_upgrade", status: "fix_available", scanConfidence: "direct_manifest_only",
    reachability: "imported", reachabilityEvidence: "Imported in first-party source — treat as reachable.", createdAt: t(1), updatedAt: t(1) }
];

// ---- Risk signals ----
state.riskSignals = state.findings.map((f) => ({
  id: `risk_${f.id}`, findingId: f.id,
  epssProbability: f.riskLevel === "critical" ? 0.62 : f.riskLevel === "high" ? 0.21 : 0.04,
  isInKev: f.id === "find_lodash", isProductionExposed: true, isDirectDependency: f.dependencyType === "direct",
  hasFix: Boolean(f.fixedVersion), notes: []
}));

// ---- Remediation job (lodash, completed → pr_ready) ----
state.remediationJobs = [
  { id: "rem_lodash", findingId: "find_lodash", projectId: "proj_web", status: "pr_ready", agent: "codex",
    branchName: "riskradar/fix-lodash-CVE-2019-10744", baseBranch: "main", startedAt: t(0), finishedAt: t(0),
    fixConfidence: 0.92, summary: "Bumped lodash 4.17.11 → 4.17.21; lockfile updated; build + tests pass.",
    changedFiles: ["package.json", "package-lock.json"], patchPath: ".riskradar/patches/rem_lodash.patch",
    rollbackStatus: "available", createdAt: t(0) }
];

// ---- Pull request ----
state.pullRequests = [
  { id: "pr_lodash", remediationJobId: "rem_lodash", provider: "github", owner: "acme", repo: "web-storefront",
    number: 142, url: "https://github.com/acme/web-storefront/pull/142",
    branchName: "riskradar/fix-lodash-CVE-2019-10744", baseBranch: "main", draft: true, status: "created", createdAt: t(0) }
];

// ---- Validation run ----
state.validationRuns = [
  { id: "val_lodash", remediationJobId: "rem_lodash", command: "npm test", status: "passed", exitCode: 0, durationMs: 18420, createdAt: t(0) }
];

// ---- Audit receipts (hash-chained look) ----
state.auditReceipts = [
  { id: "rcpt_scan", projectId: "proj_web", actorType: "system", action: "scan.completed", targetType: "scan_job", targetId: "scan_web_1",
    outputSummary: { findings: 4, scannerFindings: { gitleaks: 1 } }, changedFiles: [], redacted: true,
    receiptHash: "a1b2c3d4e5f60718", createdAt: t(0) },
  { id: "rcpt_attest", projectId: "proj_web", actorType: "system", agent: "codex", action: "remediation.validation_passed",
    targetType: "remediation_job", targetId: "rem_lodash", changedFiles: ["package.json", "package-lock.json"],
    outputSummary: { confidence: 0.92, attestation: { signed: true, algorithm: "HMAC-SHA256", keyId: "RISKRADAR_ATTESTATION_SECRET",
      statement: { package: "lodash", ecosystem: "npm", fromVersion: "4.17.11", toVersion: "4.17.21", validation: "passed", agent: "codex" } } },
    redacted: true, previousReceiptHash: "a1b2c3d4e5f60718", receiptHash: "b2c3d4e5f6071829", createdAt: t(0) }
];

// ---- Agent-config + scanner findings ----
state.agentFindings = [
  { id: "agf_1", projectId: "proj_web", filePath: ".cursor/mcp.json", field: "autoApprove", reason: "MCP server configured with autoApprove:true — enables tool execution without review.",
    severity: "high", recommendation: "Disable autoApprove or scope it to read-only tools.", createdAt: t(0) }
];
state.scannerFindings = [
  { id: "scf_1", projectId: "proj_web", scanner: "gitleaks", category: "secret", severity: "high", title: "Possible GitHub PAT in source",
    description: "A GitHub personal access token pattern was detected and masked.", evidencePath: "scripts/deploy.sh", evidenceLine: 12,
    redactedEvidence: "ghp_••••••••••••••••", source: "gitleaks", confidence: "high", remediation: "Rotate the token and move it to a secret manager.", createdAt: t(0) }
];

const outDir = path.join(root, "demo");
mkdirSync(outDir, { recursive: true });
const outFile = path.join(outDir, "seed.json");
writeFileSync(outFile, JSON.stringify(state, null, 2));
console.log("[demo] wrote", outFile, "—", state.findings.length, "findings,", state.projects.length, "projects");
