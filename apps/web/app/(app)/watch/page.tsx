import { JsonDatabase, getSettings, watchStatus } from "@riskradar/core";
import { SettingsControls } from "../../../components/SettingsControls";

export default function WatchPage() {
  const db = new JsonDatabase();
  const status = watchStatus(db);
  const settings = getSettings(db).watch;
  const stat = (label: string, value: string | number) => (
    <li className="stat"><span>{label}</span><b title={typeof value === "string" ? value : undefined}>{value}</b></li>
  );
  return (
    <>
      <div className="topline">Continuous monitoring</div>
      <h1>Watch Mode</h1>
      <p className="muted" style={{ marginTop: 8, marginBottom: 24 }}>
        Disabled by default. When enabled, RiskRadar re-scans inventoried projects on an interval, records new findings, and alerts you, but never patches automatically. Every remediation still requires approval.
      </p>

      <section className="grid two">
        <div className="panel">
          <div className="section-label">Status</div>
          <ul className="statlist">
            {stat("Enabled", status.enabled ? "yes" : "no")}
            {stat("Interval (min)", status.intervalMinutes)}
            {stat("Quiet hours", status.quietHours ?? "·")}
            {stat("Within quiet hours", status.withinQuietHours ? "yes" : "no")}
            {stat("Telegram alerts", status.telegramAlerts ? "on" : "off")}
            {stat("Last run", status.lastRunAt ?? "never")}
            {stat("Next run", status.nextRunAt ?? "·")}
            {stat("Cycles completed", status.totalCycles)}
            {stat("Findings discovered", status.findingsDiscovered)}
            {stat("Alerts sent", status.alertsSent)}
            {stat("Deduped / suppressed", status.dedupedFindings)}
            {stat("Last error", status.lastError ?? "none")}
          </ul>
        </div>
        <div className="panel">
          <div className="section-label">Controls</div>
          <SettingsControls section="watch" initial={{ enabled: settings.enabled, intervalMinutes: settings.intervalMinutes, telegramAlerts: settings.telegramAlerts, quietHours: settings.quietHours }} />
          <p className="muted" style={{ fontSize: 12, marginTop: 14 }}>Run <code className="mono">pnpm worker:watch</code> to start the loop once enabled.</p>
        </div>
      </section>
    </>
  );
}
