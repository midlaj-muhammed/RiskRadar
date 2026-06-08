import { JsonDatabase } from "@riskradar/core";
import { PaginatedTable } from "../../../components/PaginatedTable";

const REACH: Record<string, { text: string; cls: string; title: string }> = {
  imported: { text: "reachable", cls: "reach-hot", title: "Imported in first-party source; treat as reachable." },
  not_imported: { text: "likely unused", cls: "reach-dim", title: "Not imported in first-party source; likely dev-only, de-prioritized (VEX-lite)." },
  indirect: { text: "transitive", cls: "reach-muted", title: "Reached via a parent dependency, not a first-party import." },
  unknown: { text: "unknown", cls: "reach-muted", title: "Reachability could not be determined." }
};

export default function FindingsPage() {
  const state = new JsonDatabase().read();
  const rows = [...state.findings].reverse().map((finding) => {
    const vuln = state.vulnerabilities.find((v) => v.id === finding.vulnerabilityId);
    const project = state.projects.find((p) => p.id === finding.projectId);
    const reach = REACH[finding.reachability ?? "unknown"]!;
    const pkg = `${finding.packageName}@${finding.currentVersion}`;
    const missing = finding.missingRiskData.join(", ") || "none";
    return (
      <tr key={finding.id}>
        <td data-label="Vulnerability"><span className="id" title={vuln?.id}>{vuln?.id}</span></td>
        <td data-label="Project">{project?.name}</td>
        <td data-label="Package"><span className="pkg" title={pkg}>{pkg}</span></td>
        <td data-label="Risk" className={finding.riskLevel}>{finding.riskScore} {finding.riskLevel}</td>
        <td data-label="Reachability"><span className={`reach ${reach.cls}`} title={finding.reachabilityEvidence ?? reach.title}>{reach.text}</span></td>
        <td data-label="Fix Strategy">{finding.fixStrategy}</td>
        <td data-label="Missing Data" className="muted"><span className="list-trunc" title={missing}>{missing}</span></td>
      </tr>
    );
  });
  return (
    <>
      <div className="topline">Normalized vulnerability records</div>
      <h1>Findings</h1>
      <section className="panel" style={{ marginTop: 24 }}>
        <PaginatedTable
          head={<tr><th>Vulnerability</th><th>Project</th><th>Package</th><th>Risk</th><th>Reachability</th><th>Fix Strategy</th><th>Missing Data</th></tr>}
          rows={rows}
          pageSize={12}
          empty={(
            <tr>
              <td colSpan={7} className="empty-cell">
                <strong>No findings from a real scan yet.</strong>
                <span>Run a scan from the Projects page to populate findings. RiskRadar only shows results from real OSV / scanner runs, never seeded placeholders.</span>
              </td>
            </tr>
          )}
        />
      </section>
    </>
  );
}
