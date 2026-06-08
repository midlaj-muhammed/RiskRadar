import type { Finding, Project, RiskLevel, RiskSignal, Vulnerability } from "./types";

export interface RiskInput {
  vulnerability: Vulnerability;
  project: Project;
  dependencyType: Finding["dependencyType"];
  fixedVersion?: string;
  epssProbability?: number;
  epssPercentile?: number;
  isInKev?: boolean;
  hasInstallScripts?: boolean;
  isNewPackageVersion?: boolean;
  knownMalicious?: boolean;
  scanConfidence?: Finding["scanConfidence"];
}

export function riskLevel(score: number): RiskLevel {
  if (score >= 80) return "critical";
  if (score >= 60) return "high";
  if (score >= 30) return "medium";
  return "low";
}

function severityBase(vulnerability: Vulnerability): number {
  if (typeof vulnerability.cvssScore === "number") {
    if (vulnerability.cvssScore >= 9) return 40;
    if (vulnerability.cvssScore >= 7) return 30;
    if (vulnerability.cvssScore >= 4) return 18;
    if (vulnerability.cvssScore > 0) return 8;
  }
  const label = vulnerability.severity.toLowerCase();
  if (label === "critical") return 40;
  if (label === "high") return 30;
  if (label === "medium") return 18;
  if (label === "low") return 8;
  return 12;
}

export function scoreRisk(input: RiskInput): { score: number; level: RiskLevel; factors: string[]; missing: string[]; signal: Omit<RiskSignal, "id" | "findingId"> } {
  const factors: string[] = [];
  const missing: string[] = [];
  let score = severityBase(input.vulnerability);
  factors.push(`Severity contributes ${score}`);

  if (typeof input.epssPercentile === "number") {
    if (input.epssPercentile >= 0.95) {
      score += 20;
      factors.push("EPSS percentile >= 95%");
    } else if (input.epssPercentile >= 0.9) {
      score += 15;
      factors.push("EPSS percentile >= 90%");
    } else if (input.epssPercentile >= 0.75) {
      score += 10;
      factors.push("EPSS percentile >= 75%");
    } else if (input.epssPercentile >= 0.5) {
      score += 5;
      factors.push("EPSS percentile >= 50%");
    }
  } else if (input.vulnerability.cveIds.length > 0) {
    missing.push("EPSS unavailable");
  }

  if (input.isInKev) {
    score += 25;
    factors.push("CISA KEV known exploited");
  } else if (input.vulnerability.cveIds.length > 0 && input.isInKev === undefined) {
    missing.push("CISA KEV lookup unavailable");
  }

  if (input.project.productionExposed) {
    score += 15;
    factors.push("Production/internet exposure");
  } else if (input.project.deploymentUrl) {
    score += 8;
    factors.push("Deployment linked");
  }

  if (input.dependencyType === "direct") {
    score += 10;
    factors.push("Direct dependency");
  } else if (input.dependencyType === "transitive") {
    score += 4;
    factors.push("Transitive dependency");
  } else {
    missing.push("Dependency depth unknown");
  }

  if (input.fixedVersion) {
    score += 5;
    factors.push("Fix available");
  } else {
    missing.push("No fixed version found");
  }

  if (input.knownMalicious) {
    score += 35;
    factors.push("Known malicious package source match");
  }
  if (input.hasInstallScripts) {
    score += 12;
    factors.push("Install lifecycle script requires review");
  }
  if (input.isNewPackageVersion) {
    score += 8;
    factors.push("Recently published package version");
  }
  if (input.scanConfidence === "direct_manifest_only") {
    missing.push("Transitive dependencies not scanned; OSV API fallback used");
  }

  const clamped = Math.max(0, Math.min(100, Math.round(score)));
  return {
    score: clamped,
    level: riskLevel(clamped),
    factors,
    missing,
    signal: {
      epssProbability: input.epssProbability,
      epssPercentile: input.epssPercentile,
      isInKev: input.isInKev,
      isProductionExposed: input.project.productionExposed,
      isDirectDependency: input.dependencyType === "direct",
      hasFix: Boolean(input.fixedVersion),
      hasInstallScripts: input.hasInstallScripts,
      isNewPackageVersion: input.isNewPackageVersion,
      notes: missing
    }
  };
}

export function fixConfidence(input: {
  minimalVersionBump: boolean;
  lockfileUpdated: boolean;
  testsPassed: boolean;
  buildPassed: boolean;
  unrelatedFilesChanged: boolean;
  secretsTouched: boolean;
  smallDiff: boolean;
  missingTests: boolean;
  missingBuild: boolean;
  majorUpgrade: boolean;
  validationSkipped: boolean;
  newInstallScripts: boolean;
  validationFailed: boolean;
}): number {
  let score = 0;
  if (input.minimalVersionBump) score += 20;
  if (input.lockfileUpdated) score += 15;
  if (input.testsPassed) score += 25;
  if (input.buildPassed) score += 20;
  if (!input.unrelatedFilesChanged) score += 10;
  if (!input.secretsTouched) score += 5;
  if (input.smallDiff) score += 5;
  if (input.missingTests) score -= 10;
  if (input.missingBuild) score -= 10;
  if (input.majorUpgrade) score -= 15;
  if (input.validationSkipped) score -= 20;
  if (input.unrelatedFilesChanged) score -= 25;
  if (input.newInstallScripts) score -= 20;
  if (input.validationFailed) score = Math.min(score, 40);
  return Math.max(0, Math.min(100, Math.round(score)));
}
