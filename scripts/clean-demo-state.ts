import { existsSync, rmSync } from "node:fs";
import path from "node:path";
import { JsonDatabase, dataFilePath, logDir } from "../packages/core/src/index.ts";
import { safeJson } from "./live-utils.ts";

// Removes seeded demo/tap records from the local dashboard DB and the persisted
// tap-demo fixture. Local state only; never touches source. Safe to re-run.
const db = new JsonDatabase(dataFilePath());
const state = db.read();
const before = {
  projects: state.projects.length,
  findings: state.findings.length,
  remediationJobs: state.remediationJobs.length,
  approvals: state.approvals.length,
  providerConsents: (state.providerConsents ?? []).length
};

const isDemo = (id: string) => /(_tap|tap_|_demo|demo000)/.test(id);
state.projects = state.projects.filter((p) => p.id !== "proj_demo" && p.id !== "proj_tap");
state.findings = state.findings.filter((f) => !isDemo(f.id) && f.projectId !== "proj_demo" && f.projectId !== "proj_tap");
state.vulnerabilities = state.vulnerabilities.filter((v) => v.id !== "OSV-demo" && v.id !== "OSV-tap");
state.remediationJobs = state.remediationJobs.filter((j) => j.projectId !== "proj_demo" && j.projectId !== "proj_tap" && !isDemo(j.id));
state.approvals = (state.approvals ?? []).filter((a) => !isDemo(a.id));
state.providerConsents = (state.providerConsents ?? []).filter((c) => !isDemo(c.id));
if (state.settings?.repoPolicies) { delete state.settings.repoPolicies.proj_demo; delete state.settings.repoPolicies.proj_tap; }
db.write(state);

const fixture = path.join(path.dirname(logDir()), "tap-demo-fixture");
if (existsSync(fixture)) rmSync(fixture, { recursive: true, force: true });

const after = {
  projects: state.projects.length,
  findings: state.findings.length,
  remediationJobs: state.remediationJobs.length,
  approvals: state.approvals.length,
  providerConsents: (state.providerConsents ?? []).length
};
console.log(safeJson({ ok: true, removedFixture: fixture, before, after }));
