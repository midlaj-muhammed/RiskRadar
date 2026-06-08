import { getEnv } from "./env";
import type { Vulnerability } from "./types";

interface NvdResponse {
  vulnerabilities?: Array<{
    cve?: {
      id?: string;
      descriptions?: Array<{ lang?: string; value?: string }>;
      metrics?: Record<string, Array<{ cvssData?: { baseScore?: number; baseSeverity?: string } }>>;
      published?: string;
      lastModified?: string;
      references?: { referenceData?: Array<{ url?: string }> };
    };
  }>;
}

interface GhsaResponse {
  ghsa_id?: string;
  cve_id?: string;
  summary?: string;
  description?: string;
  severity?: string;
  published_at?: string;
  updated_at?: string;
  references?: string[];
  html_url?: string;
}

export async function enrichVulnerability(vulnerability: Vulnerability): Promise<Vulnerability> {
  const [nvd, ghsa] = await Promise.all([
    fetchNvd(vulnerability.cveIds),
    fetchGhsa(vulnerability.ghsaIds)
  ]);
  const next: Vulnerability = {
    ...vulnerability,
    enrichment: {
      nvd: nvd.status,
      ghsa: ghsa.status
    },
    enrichmentErrors: {
      ...(nvd.error ? { nvd: nvd.error } : {}),
      ...(ghsa.error ? { ghsa: ghsa.error } : {})
    }
  };
  if (nvd.vulnerability) {
    next.summary = preferText(next.summary, nvd.vulnerability.summary);
    next.details = next.details ?? nvd.vulnerability.details;
    next.severity = strongerSeverity(next.severity, nvd.vulnerability.severity);
    next.cvssScore = Math.max(next.cvssScore ?? 0, nvd.vulnerability.cvssScore ?? 0) || next.cvssScore;
    next.publishedAt = next.publishedAt ?? nvd.vulnerability.publishedAt;
    next.modifiedAt = newestDate(next.modifiedAt, nvd.vulnerability.modifiedAt);
    next.references = unique([...next.references, ...(nvd.vulnerability.references ?? [])]);
  }
  if (ghsa.vulnerability) {
    next.summary = preferText(next.summary, ghsa.vulnerability.summary);
    next.details = next.details ?? ghsa.vulnerability.details;
    next.severity = strongerSeverity(next.severity, ghsa.vulnerability.severity);
    next.publishedAt = next.publishedAt ?? ghsa.vulnerability.publishedAt;
    next.modifiedAt = newestDate(next.modifiedAt, ghsa.vulnerability.modifiedAt);
    next.references = unique([...next.references, ...(ghsa.vulnerability.references ?? [])]);
  }
  return next;
}

async function fetchNvd(cveIds: string[]): Promise<{ status: "found" | "not_found" | "error"; vulnerability?: Partial<Vulnerability>; error?: string }> {
  if (cveIds.length === 0) return { status: "not_found" };
  try {
    const base = getEnv("NVD_API_URL") ?? "https://services.nvd.nist.gov/rest/json/cves/2.0";
    const url = new URL(base);
    url.searchParams.set("cveIds", cveIds.slice(0, 100).join(","));
    const apiKey = getEnv("NVD_API_KEY");
    const response = await fetch(url, { headers: apiKey ? { apiKey } : undefined });
    if (!response.ok) return { status: "error", error: `NVD returned ${response.status}` };
    const body = await response.json() as NvdResponse;
    const cve = body.vulnerabilities?.[0]?.cve;
    if (!cve) return { status: "not_found" };
    const metric = Object.values(cve.metrics ?? {}).flat()[0]?.cvssData;
    return {
      status: "found",
      vulnerability: {
        summary: cve.descriptions?.find((item) => item.lang === "en")?.value,
        details: cve.descriptions?.find((item) => item.lang === "en")?.value,
        severity: metric?.baseSeverity?.toLowerCase(),
        cvssScore: metric?.baseScore,
        publishedAt: cve.published,
        modifiedAt: cve.lastModified,
        references: (cve.references?.referenceData ?? []).map((reference) => reference.url).filter((value): value is string => Boolean(value))
      }
    };
  } catch (error) {
    return { status: "error", error: error instanceof Error ? error.message : String(error) };
  }
}

async function fetchGhsa(ghsaIds: string[]): Promise<{ status: "found" | "not_found" | "error"; vulnerability?: Partial<Vulnerability>; error?: string }> {
  if (ghsaIds.length === 0) return { status: "not_found" };
  try {
    const token = getEnv("GITHUB_TOKEN");
    const base = getEnv("GHSA_API_URL") ?? "https://api.github.com/advisories";
    const response = await fetch(`${base}/${encodeURIComponent(ghsaIds[0]!)}`, {
      headers: {
        accept: "application/vnd.github+json",
        ...(token ? { authorization: `Bearer ${token}` } : {})
      }
    });
    if (response.status === 404) return { status: "not_found" };
    if (!response.ok) return { status: "error", error: `GitHub Advisory API returned ${response.status}` };
    const body = await response.json() as GhsaResponse;
    return {
      status: "found",
      vulnerability: {
        summary: body.summary,
        details: body.description,
        severity: body.severity,
        publishedAt: body.published_at,
        modifiedAt: body.updated_at,
        references: unique([...(body.references ?? []), body.html_url].filter((value): value is string => Boolean(value)))
      }
    };
  } catch (error) {
    return { status: "error", error: error instanceof Error ? error.message : String(error) };
  }
}

function preferText(current: string, candidate?: string): string {
  return candidate && candidate.length > current.length ? candidate : current;
}

function newestDate(current?: string, candidate?: string): string | undefined {
  if (!current) return candidate;
  if (!candidate) return current;
  return Date.parse(candidate) > Date.parse(current) ? candidate : current;
}

function strongerSeverity(current: string, candidate?: string): string {
  const rank: Record<string, number> = { unknown: 0, low: 1, medium: 2, moderate: 2, high: 3, critical: 4 };
  if (!candidate) return current;
  return (rank[candidate.toLowerCase()] ?? 0) > (rank[current.toLowerCase()] ?? 0) ? candidate.toLowerCase() : current;
}

function unique(values: string[]): string[] {
  return [...new Set(values)];
}
