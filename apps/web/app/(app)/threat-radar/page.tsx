import { JsonDatabase, RiskRadarService } from "@riskradar/core";

const humanize = (key: string) =>
  key
    .replace(/([A-Z])/g, " $1")
    .replace(/^./, (c) => c.toUpperCase())
    .trim();

export default function ThreatRadarPage() {
  const radar = new RiskRadarService(new JsonDatabase()).threatRadar();
  return (
    <>
      <div className="topline">Counts backed by persisted scan records</div>
      <h1>Threat Radar</h1>
      <section className="panel" style={{ marginTop: 24 }}>
        <div className="radar">
          {Object.entries(radar).filter(([, value]) => typeof value === "number").map(([key, value]) => (
            <div className="radar-item" key={key}>
              <div className="metric-label" title={key}>{humanize(key)}</div>
              <div className="metric-value">{value}</div>
            </div>
          ))}
        </div>
      </section>
    </>
  );
}
