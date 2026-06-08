"use client";

import { useState } from "react";

type WatchControls = { enabled: boolean; intervalMinutes: number; telegramAlerts: boolean; quietHours?: string };
type FailoverControls = { mode: "ask" | "automatic" | "disabled"; allowCloudFailover: boolean; allowLocalFailover: boolean; requireConsentForLowerTrust: boolean };

export function SettingsControls(props: { section: "watch"; initial: WatchControls } | { section: "failover"; initial: FailoverControls }) {
  const [state, setState] = useState<Record<string, unknown>>(props.initial as Record<string, unknown>);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | undefined>();

  async function save(part: Record<string, unknown>) {
    const next = { ...state, ...part };
    setState(next);
    setSaving(true);
    setError(undefined);
    try {
      const response = await fetch("/api/settings", {
        method: "PATCH",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ [props.section]: part })
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : "save failed");
    } finally {
      setSaving(false);
    }
  }

  const Toggle = ({ label, name, hint }: { label: string; name: string; hint?: string }) => (
    <label className="control-row">
      <span>
        {label}
        {hint ? <span className="muted" style={{ display: "block", fontSize: 12 }}>{hint}</span> : null}
      </span>
      <input type="checkbox" checked={Boolean(state[name])} onChange={(event) => save({ [name]: event.target.checked })} />
    </label>
  );

  return (
    <div className="controls">
      {props.section === "watch" ? (
        <>
          <Toggle label="Watch mode enabled" name="enabled" hint="Periodically re-scans inventoried projects. Never auto-patches." />
          <Toggle label="Telegram alerts" name="telegramAlerts" hint="Alert on new findings (dashboard-only if Telegram is not configured)." />
          <label className="control-row">
            <span>Interval (minutes)</span>
            <input type="number" min={5} value={Number(state.intervalMinutes ?? 60)} onChange={(event) => save({ intervalMinutes: Number(event.target.value) })} style={{ width: 90 }} />
          </label>
        </>
      ) : (
        <>
          <label className="control-row">
            <span>Failover mode<span className="muted" style={{ display: "block", fontSize: 12 }}>ask = consent before lower-trust providers</span></span>
            <select value={String(state.mode ?? "ask")} onChange={(event) => save({ mode: event.target.value })}>
              <option value="ask">ask</option>
              <option value="automatic">automatic</option>
              <option value="disabled">disabled</option>
            </select>
          </label>
          <Toggle label="Allow cloud→cloud failover" name="allowCloudFailover" />
          <Toggle label="Allow local model failover" name="allowLocalFailover" hint="When off, a local model is only used after explicit consent." />
          <Toggle label="Require consent before lower-trust provider" name="requireConsentForLowerTrust" />
        </>
      )}
      <div className="muted" style={{ fontSize: 12 }}>{saving ? "Saving…" : error ? `Error: ${error}` : "Saved to local settings."}</div>
    </div>
  );
}
