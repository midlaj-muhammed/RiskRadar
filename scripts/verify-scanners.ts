import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { runProjectScanners } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Builds a synthetic risky workspace and verifies the built-in scanners actually
// detect issues (CI hardening, lightweight secret, suspicious package). External
// scanners report tool_missing honestly when not installed. Secrets stay masked.
const root = path.join(os.tmpdir(), `riskradar-scanners-verify-${Date.now()}`);
try {
  mkdirSync(path.join(root, ".github", "workflows"), { recursive: true });
  writeFileSync(path.join(root, ".github", "workflows", "ci.yml"), "permissions: write-all\njobs:\n  a:\n    steps:\n      - uses: actions/checkout@v4\n");
  writeFileSync(path.join(root, "package.json"), JSON.stringify({ name: "risky", dependencies: { lodash: "4.17.20" }, scripts: { postinstall: "node setup.js" } }, null, 2));
  // A FAKE GitHub PAT-shaped token (not a real secret) that both Gitleaks and the
  // built-in detector flag — the canonical AKIA example key is allowlisted by Gitleaks.
  const fakeToken = "ghp_aB3dEfGh1jKlMnOpQrStUvWx0123456789YZab";
  writeFileSync(path.join(root, "leak.env"), `GH_TOKEN=${fakeToken}\n`);

  const results = runProjectScanners(root, "verify");
  const summary = results.map((r) => ({ scanner: r.scanner, category: r.category, status: r.status, findings: r.findings.length, installHint: r.status === "tool_missing" ? r.installHint : undefined }));
  const serialized = JSON.stringify(results);
  const ci = results.find((r) => r.category === "ci");
  const secret = results.find((r) => r.category === "secret");
  const malware = results.find((r) => r.category === "malware");
  const ok = (ci?.findings.length ?? 0) > 0
    && (secret?.findings.length ?? 0) > 0
    && (malware?.findings.length ?? 0) > 0
    && !serialized.includes(fakeToken); // raw secret never stored (masked)

  console.log(safeJson({ ok, secretScanner: secret?.scanner, scanners: summary, rawSecretLeaked: serialized.includes(fakeToken) }));
  if (!ok) process.exit(1);
} finally {
  rmSync(root, { recursive: true, force: true });
}
