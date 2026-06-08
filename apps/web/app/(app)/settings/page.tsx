import { agentProviderReadiness, integrationHealth, listAgentAdapters } from "@riskradar/core";

export default function SettingsPage() {
  const providers = agentProviderReadiness();
  const selected = providers.find((provider) => provider.selected)?.id ?? "codex";
  return (
    <>
      <div className="topline">Configuration-gated integrations</div>
      <h1>Settings</h1>
      <section className="panel" style={{ marginTop: 24 }}>
        <h2>Model Providers (BYO)</h2>
        <p className="muted" style={{ marginTop: 0 }}>
          Selected provider: <span className="badge">{selected}</span>. Only Codex edits the repo directly; OpenRouter, OpenAI-compatible, and Ollama return strict JSON plans that RiskRadar applies itself. Required env shows names only, never secret values.
        </p>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Provider</th><th>Status</th><th>Applies via</th><th>Model edits repo</th><th>Required env</th></tr></thead>
            <tbody>
              {providers.map((provider) => {
                const env = provider.requiredEnv.join(", ") || "·";
                return (
                  <tr key={provider.id}>
                    <td data-label="Provider">{provider.label}{provider.selected ? " ★" : ""}</td>
                    <td data-label="Status" className={provider.status === "configured" ? "ok" : provider.status === "unavailable" ? "high" : "medium"}>{provider.status}</td>
                    <td data-label="Applies via">{provider.applyStrategy}</td>
                    <td data-label="Model edits repo">{provider.modelEditsRepo ? "yes" : "no"}</td>
                    <td data-label="Required env"><span className="list-trunc mono" title={env}>{env}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel" style={{ marginTop: 24 }}>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Integration</th><th>Status</th><th>Message</th><th>Required env</th></tr></thead>
            <tbody>
              {integrationHealth().map((item) => {
                const env = item.requiredEnv?.join(", ") ?? "";
                return (
                  <tr key={item.name}>
                    <td data-label="Integration">{item.name}</td>
                    <td data-label="Status" className={item.status === "available" || item.status === "configured" ? "ok" : "medium"}>{item.status}</td>
                    <td data-label="Message"><span className="list-trunc" title={item.message}>{item.message}</span></td>
                    <td data-label="Required env"><span className="list-trunc mono" title={env}>{env || "·"}</span></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </section>
      <section className="panel" style={{ marginTop: 14 }}>
        <h2>Agent Adapters</h2>
        <div className="table-scroll">
          <table>
            <thead><tr><th>Adapter</th><th>Status</th><th>Workspace edits</th><th>Message</th></tr></thead>
            <tbody>
              {listAgentAdapters().map((item) => (
                <tr key={item.id}>
                  <td data-label="Adapter">{item.label}</td>
                  <td data-label="Status" className={item.status === "configured" ? "ok" : "medium"}>{item.status}</td>
                  <td data-label="Workspace edits">{item.canModifyWorkspace ? "yes" : "plan only"}</td>
                  <td data-label="Message"><span className="list-trunc" title={item.message}>{item.message}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
