import { detectScannerTools, scannerCoverage } from "@riskradar/core";

export default function ScannersPage() {
  const coverage = scannerCoverage();
  const tools = detectScannerTools();
  return (
    <>
      <div className="topline">Real scanner orchestration</div>
      <h1>Scanner Coverage</h1>
      <p className="muted" style={{ marginTop: 8, marginBottom: 24 }}>
        Status is honest: green only where a real check can run. External scanners show <code className="mono">tool_missing</code> with an install hint until installed.
      </p>

      <section className="cardgrid">
        {coverage.map((entry) => (
          <div className="statuscard" key={entry.category}>
            <div className="head">
              <h3>{entry.label}</h3>
              <span className={`status-badge ${entry.status}`}>{entry.status}</span>
            </div>
            <div className="muted" style={{ fontSize: 13 }}>{entry.message}</div>
            <div style={{ marginTop: 12, display: "flex", gap: 8, flexWrap: "wrap" }}>
              <span className="badge">{entry.scanner}</span>
              <span className="pill">{entry.confidence} confidence</span>
            </div>
            {entry.installHint ? <div className="hint">{entry.installHint}</div> : null}
          </div>
        ))}
      </section>

      <section className="panel" style={{ marginTop: 24 }}>
        <div className="section-label">External tools</div>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Tool</th><th>Category</th><th>Status</th><th>Command</th><th>Version</th></tr></thead>
            <tbody>
              {tools.map((tool) => (
                <tr key={tool.id}>
                  <td data-label="Tool">{tool.label}</td>
                  <td data-label="Category">{tool.category}</td>
                  <td data-label="Status"><span className={`status-badge ${tool.status}`}>{tool.status}</span></td>
                  <td data-label="Command"><span className="path" title={tool.command}>{tool.command}</span></td>
                  <td data-label="Version"><span className="id-sm" title={tool.version ?? ""}>{tool.version ?? "·"}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
