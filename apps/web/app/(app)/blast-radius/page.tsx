import { JsonDatabase, RiskRadarService } from "@riskradar/core";
import { PaginatedTable } from "../../../components/PaginatedTable";

export default function BlastRadiusPage() {
  const data = new RiskRadarService(new JsonDatabase()).blastRadius();
  const rows = [...data].reverse().map((row) => {
    const prShort = row.prUrl
      ? row.prUrl
          .replace(/^https?:\/\/(www\.)?github\.com\//, "")
          .replace(/^https?:\/\//, "")
      : null;
    return (
      <tr key={row.finding.id}>
        <td data-label="Advisory"><span className="id" title={row.vulnerability?.id}>{row.vulnerability?.id}</span></td>
        <td data-label="Project">{row.project?.name}</td>
        <td data-label="Source">{row.project?.sourceType}</td>
        <td data-label="Dependency">{row.directness}</td>
        <td data-label="Fix">{row.fixAvailable ? <span className="pkg" title={row.finding.fixedVersion}>{row.finding.fixedVersion}</span> : <span className="muted">blocked</span>}</td>
        <td data-label="Exposed">{row.internetFacing ? "yes" : "unknown/no"}</td>
        <td data-label="Job">{row.codexJobStatus ?? <span className="muted">none</span>}</td>
        <td data-label="PR">{row.prUrl ? <a className="url-chip" href={row.prUrl} title={row.prUrl} target="_blank" rel="noreferrer">{prShort}</a> : <span className="muted">none</span>}</td>
        <td data-label="Validation">{row.validationPassed ? "passed" : "not passed"}</td>
      </tr>
    );
  });
  return (
    <>
      <div className="topline">Finding to project impact mapping</div>
      <h1>Blast Radius Map</h1>
      <section className="panel" style={{ marginTop: 24 }}>
        <PaginatedTable
          head={<tr><th>Advisory</th><th>Project</th><th>Source</th><th>Dependency</th><th>Fix</th><th>Exposed</th><th>Job</th><th>PR</th><th>Validation</th></tr>}
          rows={rows}
          pageSize={12}
          empty={<tr><td colSpan={9} className="muted">No blast radius exists until a real scan stores findings.</td></tr>}
        />
      </section>
    </>
  );
}
