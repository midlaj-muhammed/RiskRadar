import { JsonDatabase } from "@riskradar/core";
import { PaginatedTable } from "../../../components/PaginatedTable";

export default function ApprovalsPage() {
  const state = new JsonDatabase().read();
  const rows = [...state.approvals].reverse().map((approval) => (
    <tr key={approval.id}>
      <td data-label="Approval ID"><span className="id" title={approval.id}>{approval.id}</span></td>
      <td data-label="Job"><span className="id" title={approval.remediationJobId}>{approval.remediationJobId}</span></td>
      <td data-label="Channel">{approval.channel}</td>
      <td data-label="Sent" className="muted"><span className="list-trunc" title={approval.createdAt}>{approval.createdAt}</span></td>
      <td data-label="Expires" className="muted"><span className="list-trunc" title={approval.expiresAt}>{approval.expiresAt}</span></td>
      <td data-label="Status">{approval.status}</td>
    </tr>
  ));
  return (
    <>
      <div className="topline">Phone Approval Gate</div>
      <h1>Approvals</h1>
      <section className="panel" style={{ marginTop: 24 }}>
        <PaginatedTable
          head={<tr><th>Approval ID</th><th>Job</th><th>Channel</th><th>Sent</th><th>Expires</th><th>Status</th></tr>}
          rows={rows}
          pageSize={12}
          empty={<tr><td colSpan={6} className="muted">No approval requests. Telegram remains unavailable until configured.</td></tr>}
        />
      </section>
    </>
  );
}
