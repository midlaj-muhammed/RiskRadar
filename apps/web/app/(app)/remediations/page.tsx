import { JsonDatabase, codexStatus } from "@riskradar/core";
import { PaginatedTable } from "../../../components/PaginatedTable";

export default function RemediationsPage() {
  const state = new JsonDatabase().read();
  const codex = codexStatus();
  const rows = [...state.remediationJobs].reverse().map((job) => {
    const patch = job.patchPath ?? "none";
    const files = job.changedFiles.join(", ");
    const err = job.errorMessage ?? "";
    return (
      <tr key={job.id}>
        <td data-label="Job"><span className="id" title={job.id}>{job.id}</span></td>
        <td data-label="Agent">{job.agent}</td>
        <td data-label="Status">{job.status}</td>
        <td data-label="Confidence">{job.fixConfidence ?? "unknown"}</td>
        <td data-label="Patch">{job.patchPath ? <span className="path" title={patch}>{patch}</span> : <span className="muted">none</span>}</td>
        <td data-label="Rollback">{job.rollbackStatus ?? "unknown"}</td>
        <td data-label="Changed files"><span className="list-trunc" title={files}>{files}</span></td>
        <td data-label="Error"><span className="list-trunc" title={err}>{err}</span></td>
      </tr>
    );
  });
  return (
    <>
      <div className="topline">Codex Remediation Timeline</div>
      <h1>Remediation Jobs</h1>
      <section className="panel" style={{ marginTop: 24 }}>
        <h2>Codex status</h2>
        <p className={codex.configured ? "ok" : "medium"}>{codex.message}</p>
      </section>
      <section className="panel" style={{ marginTop: 14 }}>
        <PaginatedTable
          head={<tr><th>Job</th><th>Agent</th><th>Status</th><th>Confidence</th><th>Patch</th><th>Rollback</th><th>Changed files</th><th>Error</th></tr>}
          rows={rows}
          pageSize={12}
          empty={<tr><td colSpan={8} className="muted">No remediation jobs yet. Jobs will not claim Codex ran unless the CLI really executed.</td></tr>}
        />
      </section>
    </>
  );
}
