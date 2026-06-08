import { getEnv } from "./env";

export interface EpssRecord {
  cve: string;
  epss: number;
  percentile: number;
}

export async function fetchEpss(cveIds: string[]): Promise<Map<string, EpssRecord>> {
  const map = new Map<string, EpssRecord>();
  if (cveIds.length === 0) return map;
  try {
    const url = `${getEnv("EPSS_API_URL") ?? "https://api.first.org/data/v1/epss"}?cve=${encodeURIComponent(cveIds.join(","))}`;
    const response = await fetch(url);
    if (!response.ok) return map;
    const json = (await response.json()) as { data?: Array<{ cve: string; epss: string; percentile: string }> };
    for (const row of json.data ?? []) {
      map.set(row.cve, { cve: row.cve, epss: Number(row.epss), percentile: Number(row.percentile) });
    }
  } catch {
    return map;
  }
  return map;
}

export interface KevRecord {
  cveID: string;
  dueDate?: string;
  knownRansomwareCampaignUse?: string;
}

export async function fetchKev(cveIds: string[]): Promise<Map<string, KevRecord>> {
  const result = new Map<string, KevRecord>();
  if (cveIds.length === 0) return result;
  try {
    const response = await fetch(getEnv("CISA_KEV_URL") ?? "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json");
    if (!response.ok) return result;
    const json = (await response.json()) as { vulnerabilities?: KevRecord[] };
    const wanted = new Set(cveIds);
    for (const record of json.vulnerabilities ?? []) {
      if (wanted.has(record.cveID)) result.set(record.cveID, record);
    }
  } catch {
    return result;
  }
  return result;
}
