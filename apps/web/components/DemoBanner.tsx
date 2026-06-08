/**
 * Shows a "demo data" notice when RISKRADAR_DEMO=true (used by the hosted
 * preview). Renders nothing in normal local/self-hosted mode so real scans are
 * never labeled as demo.
 */
export function DemoBanner() {
  if (process.env.RISKRADAR_DEMO !== "true") return null;
  return (
    <div className="demo-banner">
      <span className="demo-dot" />
      <span>
        <b>Demo data.</b> This hosted preview shows seeded findings so you can explore the UI. For real scans of your repos, self-host or run the CLI. See the{" "}
        <a href="https://github.com/midlaj-muhammed/RiskRadar.git" target="_blank" rel="noreferrer">README</a>.
      </span>
    </div>
  );
}
