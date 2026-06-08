const baseUrl = (process.argv[2] ?? process.env.RISKRADAR_SMOKE_BASE_URL ?? "").replace(/\/$/, "");

if (!baseUrl) {
  console.error("Usage: node scripts/smoke-app.mjs http://127.0.0.1:3000");
  process.exit(2);
}

const checks = [
  { path: "/", type: "html" },
  { path: "/api/health", type: "json", assert: (body) => body.ok === true && body.productionReady === false && body.queueMode === "inline" && body.services && Array.isArray(body.missingIntegrations) && Array.isArray(body.scannerCoverage) && body.watch && typeof body.watch.enabled === "boolean" },
  { path: "/api/projects", type: "json" },
  { path: "/api/findings", type: "json" },
  { path: "/api/threat-radar", type: "json" },
  { path: "/api/blast-radius", type: "json" },
  { path: "/api/audit", type: "json" },
  { path: "/api/approvals", type: "json" },
  { path: "/api/scanners", type: "json", assert: (body) => body.ok === true && Array.isArray(body.coverage) && Array.isArray(body.tools) },
  { path: "/api/watch", type: "json", assert: (body) => body.ok === true && body.watch && typeof body.watch.enabled === "boolean" },
  { path: "/api/providers", type: "json", assert: (body) => body.ok === true && Array.isArray(body.providers) },
  { path: "/api/settings", type: "json", assert: (body) => body.ok === true && body.settings && body.settings.failover }
];

// No endpoint may leak a secret value.
const SECRET_PATTERNS = [/gh[pousr]_[A-Za-z0-9_]{20,}/, /github_pat_[A-Za-z0-9_]{20,}/, /sk-[A-Za-z0-9_-]{20,}/, /xox[baprs]-[A-Za-z0-9-]{10,}/, /AKIA[0-9A-Z]{16}/, /\b\d{8,10}:[A-Za-z0-9_-]{30,}\b/];

const results = [];
for (const check of checks) {
  const started = Date.now();
  const response = await fetch(`${baseUrl}${check.path}`);
  const text = await response.text();
  if (!response.ok) {
    throw new Error(`${check.path} returned ${response.status}: ${text.slice(0, 200)}`);
  }
  const leak = SECRET_PATTERNS.find((pattern) => pattern.test(text));
  if (leak) {
    throw new Error(`${check.path} response leaked a secret-looking value (pattern ${leak}).`);
  }
  let body;
  if (check.type === "json") {
    body = JSON.parse(text);
    if (check.assert && !check.assert(body)) {
      throw new Error(`${check.path} returned a fake-ready or malformed payload`);
    }
  } else if (!text.includes("Watch Commander")) {
    throw new Error(`${check.path} did not render the dashboard`);
  }
  results.push({ path: check.path, status: response.status, bytes: text.length, ms: Date.now() - started });
}

console.log(JSON.stringify({ ok: true, baseUrl, results }, null, 2));
