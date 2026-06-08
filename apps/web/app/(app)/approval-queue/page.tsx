import { JsonDatabase } from "@riskradar/core";

export default function ApprovalQueuePage() {
  const state = new JsonDatabase().read();
  const pendingApprovals = state.approvals.filter((approval) => approval.status === "pending");
  const pendingConsents = (state.providerConsents ?? []).filter((consent) => consent.status === "pending");
  const watchAlerts = (state.watchAlerts ?? []).slice(-15).reverse();

  return (
    <>
      <div className="topline">Everything waiting on you</div>
      <h1>Approval Queue</h1>
      <p className="muted" style={{ marginTop: 8, marginBottom: 24 }}>
        Remediation approvals, provider-failover consent requests, and watch-mode alerts. RiskRadar never auto-merges or auto-deploys; these are the human gates.
      </p>

      <section className="panel">
        <div className="section-label">Remediation approvals ({pendingApprovals.length} pending)</div>
        {pendingApprovals.length === 0 ? (
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>No remediation approvals pending.</p>
        ) : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Approval</th><th>Job</th><th>Channel</th><th>Expires</th></tr></thead>
              <tbody>
                {pendingApprovals.map((approval) => (
                  <tr key={approval.id}>
                    <td data-label="Approval"><span className="id" title={approval.id}>{approval.id}</span></td>
                    <td data-label="Job"><span className="id" title={approval.remediationJobId}>{approval.remediationJobId}</span></td>
                    <td data-label="Channel">{approval.channel}</td>
                    <td data-label="Expires" className="muted"><span className="list-trunc" title={approval.expiresAt}>{approval.expiresAt}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel" style={{ marginTop: 24 }}>
        <div className="section-label">Provider failover consent ({pendingConsents.length} pending)</div>
        {pendingConsents.length === 0 ? (
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>No provider-failover consent requests pending.</p>
        ) : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Failed provider</th><th>Candidate</th><th>Trust</th><th>Requested</th></tr></thead>
              <tbody>
                {pendingConsents.map((consent) => (
                  <tr key={consent.id}>
                    <td data-label="Failed provider">{consent.failedProvider}</td>
                    <td data-label="Candidate">{consent.candidateProvider}</td>
                    <td data-label="Trust"><span className="badge">{consent.candidateTrust}</span></td>
                    <td data-label="Requested" className="muted"><span className="list-trunc" title={consent.createdAt}>{consent.createdAt}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>

      <section className="panel" style={{ marginTop: 24 }}>
        <div className="section-label">Watch-mode alerts ({watchAlerts.length})</div>
        {watchAlerts.length === 0 ? (
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>No watch alerts. Enable Watch Mode to monitor continuously.</p>
        ) : (
          <div className="table-scroll">
            <table>
              <thead><tr><th>Package</th><th>Advisory</th><th>Severity</th><th>Channel</th><th>When</th></tr></thead>
              <tbody>
                {watchAlerts.map((alert) => (
                  <tr key={alert.id}>
                    <td data-label="Package"><span className="pkg" title={alert.packageName}>{alert.packageName}</span></td>
                    <td data-label="Advisory"><span className="id" title={alert.advisoryId}>{alert.advisoryId}</span></td>
                    <td data-label="Severity" className={alert.severity}>{alert.severity}</td>
                    <td data-label="Channel">{alert.channel}</td>
                    <td data-label="When" className="muted"><span className="list-trunc" title={alert.sentAt}>{alert.sentAt}</span></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </section>
    </>
  );
}
