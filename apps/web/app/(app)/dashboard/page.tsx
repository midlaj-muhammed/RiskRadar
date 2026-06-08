import { JsonDatabase, RiskRadarService, agentProviderReadiness, integrationHealth } from "@riskradar/core";
import { Activity, AlertTriangle, ShieldCheck, BellRing, ArrowRight } from "lucide-react";

const REACH: Record<string, { text: string; cls: string; title: string }> = {
  imported: { text: "reachable", cls: "reach-hot", title: "Imported in first-party source; treat as reachable." },
  not_imported: { text: "likely unused", cls: "reach-dim", title: "Not imported in first-party source; likely dev-only, de-prioritized (VEX-lite)." },
  indirect: { text: "transitive", cls: "reach-muted", title: "Reached via a parent dependency, not a first-party import." },
  unknown: { text: "unknown", cls: "reach-muted", title: "Reachability could not be determined." }
};

export default function Dashboard() {
  const db = new JsonDatabase();
  const state = db.read();
  const service = new RiskRadarService(db);
  const radar = service.threatRadar();
  const health = integrationHealth();
  const providers = agentProviderReadiness();
  const selectedProvider = providers.find((provider) => provider.selected) ?? providers[0];

  const openFindings = state.findings.filter((finding) => finding.status !== "resolved").length;
  const ready = health.filter((item) => item.status === "configured" || item.status === "available");
  const notReady = health.filter((item) => item.status !== "configured" && item.status !== "available");

  const kpis = [
    { label: "Open findings", value: openFindings, foot: "From real scans", Icon: Activity, tone: "" },
    { label: "Critical / high", value: radar.criticalHighRisks, foot: "Risk engine output", Icon: AlertTriangle, tone: radar.criticalHighRisks > 0 ? "critical" : "ok" },
    { label: "Fixes available", value: radar.fixesAvailable, foot: "Safe upgrade known", Icon: ShieldCheck, tone: "ok" },
    { label: "Approvals pending", value: radar.approvalsPending, foot: "Signed queue", Icon: BellRing, tone: radar.approvalsPending > 0 ? "medium" : "" }
  ];

  const signals = [
    { label: "Actively exploited (KEV)", value: radar.activelyExploited, tone: radar.activelyExploited > 0 ? "critical" : "" },
    { label: "Malicious package alerts", value: radar.maliciousPackageAlerts, tone: radar.maliciousPackageAlerts > 0 ? "medium" : "" },
    { label: "Fixes blocked", value: radar.fixesBlocked, tone: "" },
    { label: "Remediation jobs running", value: radar.jobsRunning, tone: "" },
    { label: "Advisories scanned", value: radar.advisoriesScanned, tone: "" }
  ];

  const findings = state.findings.slice(-8).reverse();

  return (
    <>
      <div className="page-head">
        <div className="topline">Cross-project CVE &amp; supply-chain response</div>
        <div className="head-row">
          <h1>Watch Commander</h1>
          <div className="head-actions">
            <span className="badge">remediation · {selectedProvider?.id ?? "codex"}</span>
            <a className="pill-link" href="/threat-radar">Threat radar <ArrowRight size={13} /></a>
          </div>
        </div>
      </div>

      <section className="grid metrics">
        {kpis.map(({ label, value, foot, Icon, tone }) => (
          <div className="card kpi" key={label}>
            <div className="kpi-top">
              <div className="metric-label">{label}</div>
              <Icon size={16} className={`kpi-icon ${tone}`} />
            </div>
            <div className={`metric-value ${tone}`}>{value}</div>
            <div className="metric-foot">{foot}</div>
          </div>
        ))}
      </section>

      <section className="grid two">
        <div className="panel">
          <div className="section-label">Affected projects</div>
          <div className="table-scroll">
            <table>
              <thead>
                <tr>
                  <th>Project</th>
                  <th>Risk</th>
                  <th>Package</th>
                  <th>Reachability</th>
                  <th>Fix</th>
                  <th>Status</th>
                </tr>
              </thead>
              <tbody>
                {findings.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="empty-cell">
                      <strong>No findings yet.</strong>
                      <span>Add a project and run a scan to populate the threat radar. Local scans need <code>RISKRADAR_LOCAL_ROOTS</code>; GitHub scans need <code>GITHUB_TOKEN</code>.</span>
                      <a className="pill-link" href="/projects">Go to Projects <ArrowRight size={13} /></a>
                    </td>
                  </tr>
                ) : findings.map((finding) => {
                  const project = state.projects.find((item) => item.id === finding.projectId);
                  const reach = REACH[finding.reachability ?? "unknown"]!;
                  const pkg = `${finding.packageName}@${finding.currentVersion}`;
                  return (
                    <tr key={finding.id}>
                      <td data-label="Project">{project?.name ?? "Unknown"}</td>
                      <td data-label="Risk" className={finding.riskLevel}>{finding.riskScore}/100</td>
                      <td data-label="Package"><span className="pkg" title={pkg}>{pkg}</span></td>
                      <td data-label="Reachability"><span className={`reach ${reach.cls}`} title={finding.reachabilityEvidence ?? reach.title}>{reach.text}</span></td>
                      <td data-label="Fix">{finding.fixedVersion ? <span className="pkg" title={`→ ${finding.fixedVersion}`}>→ {finding.fixedVersion}</span> : "manual review"}</td>
                      <td data-label="Status">{finding.status}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div className="panel">
          <div className="section-label">Posture</div>
          <ul className="statlist">
            {signals.map((signal) => (
              <li className="stat" key={signal.label}>
                <span>{signal.label}</span>
                <b className={signal.value > 0 ? signal.tone : "muted"}>{signal.value}</b>
              </li>
            ))}
          </ul>

          <div className="section-label" style={{ marginTop: 24 }}>
            Integrations · {ready.length}/{health.length} ready
          </div>
          {notReady.length === 0 ? (
            <p className="muted" style={{ margin: 0, fontSize: 13 }}>All integrations configured.</p>
          ) : (
            <div className="chips">
              {notReady.map((item) => (
                <span className="chip" key={item.name} title={item.message}>
                  <span className={`dot ${item.status === "unavailable" ? "bad" : "warn"}`} />
                  {item.name}
                </span>
              ))}
            </div>
          )}
        </div>
      </section>
    </>
  );
}
