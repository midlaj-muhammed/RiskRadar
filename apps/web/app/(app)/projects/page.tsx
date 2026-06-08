import { RiskRadarService, JsonDatabase } from "@riskradar/core";
import { PaginatedTable } from "../../../components/PaginatedTable";

export default function ProjectsPage() {
  const projects = new RiskRadarService(new JsonDatabase()).listProjects();
  const rows = [...projects].reverse().map((project) => (
    <tr key={project.id}>
      <td data-label="Name">{project.name}</td>
      <td data-label="Source">{project.sourceType}</td>
      <td data-label="Package manager">{project.packageManager}</td>
      <td data-label="Deployment">{project.productionExposed ? "Production" : project.deploymentProvider}</td>
      <td data-label="Last scan">{project.lastScanStatus ?? "never"}</td>
      <td data-label="Findings">{project.openFindings}</td>
    </tr>
  ));
  return (
    <>
      <div className="topline">Inventory</div>
      <h1>Projects</h1>
      <section className="panel" style={{ marginTop: 24 }}>
        <h2>Add Project</h2>
        <form className="form" action="/api/projects" method="post">
          <div className="field">
            <label>Source</label>
            <select name="sourceType" defaultValue="local">
              <option value="local">Local folder</option>
              <option value="github">GitHub repo</option>
            </select>
          </div>
          <div className="field"><label>Name</label><input name="name" placeholder="api-server" /></div>
          <div className="field"><label>Local path</label><input name="localPath" placeholder="C:\\projects\\api-server" /></div>
          <div className="field"><label>GitHub owner/repo</label><input name="github" placeholder="owner/repo" /></div>
          <button className="button" type="submit">Add</button>
        </form>
      </section>
      <section className="panel" style={{ marginTop: 14 }}>
        <h2>Watched Projects</h2>
        <PaginatedTable
          head={<tr><th>Name</th><th>Source</th><th>Package manager</th><th>Deployment</th><th>Last scan</th><th>Findings</th></tr>}
          rows={rows}
          pageSize={12}
          empty={<tr><td colSpan={6} className="muted">No projects watched yet. Add a GitHub repo or allowlisted local folder.</td></tr>}
        />
      </section>
    </>
  );
}
