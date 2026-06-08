import { execSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { safeJson } from "./live-utils.ts";

// Static repo hygiene audit. HARD failures: tracked secrets/env, tracked
// generated files, missing required docs/scripts. SOFT (reported, classified):
// fake/placeholder/TODO terms — allowed in tests/fixtures/docs, must-fix only in
// production code paths.
function tracked(): string[] {
  return execSync("git ls-files", { encoding: "utf8" }).split(/\r?\n/).filter(Boolean);
}

const files = tracked();
const isTestOrFixtureOrDoc = (f: string) => /(__tests__|tests\/|fixtures\/|\.test\.|docs\/|\.md$|\.env\.example$|scripts\/)/.test(f);
const isProduction = (f: string) => /^(packages\/core\/src|apps\/web\/app|apps\/web\/components|apps\/worker\/src|apps\/mcp\/src)\//.test(f) && !/__tests__/.test(f);

const hard: string[] = [];
const soft: Array<{ term: string; file: string; line: number; text: string }> = [];

// HARD: no .env tracked, no generated tracked
if (files.includes(".env")) hard.push(".env is tracked");
for (const f of files) {
  if (/(^|\/)node_modules\//.test(f)) hard.push(`node_modules tracked: ${f}`);
  if (/(^|\/)\.next\//.test(f)) hard.push(`.next tracked: ${f}`);
  if (/(^|\/)\.riskradar\//.test(f)) hard.push(`.riskradar tracked: ${f}`);
}

// HARD: no real secret tokens in tracked NON-test files
const SECRET_RE = [/gh[pousr]_[A-Za-z0-9]{30,}/, /github_pat_[A-Za-z0-9_]{40,}/, /xox[baprs]-[A-Za-z0-9-]{20,}/];
// fake/placeholder term scan (soft, classified)
const TERMS = ["TODO", "FIXME", "coming soon", "not implemented", "hardcoded success", "fake PR", "fake CVE", "fake approval", "fake codex"];

for (const f of files) {
  if (!/\.(ts|tsx|mjs|js|json|md)$/.test(f) || !existsSync(f)) continue;
  let content = "";
  try { content = readFileSync(f, "utf8"); } catch { continue; }
  // secret scan excludes tests/fixtures/example
  if (!isTestOrFixtureOrDoc(f)) {
    for (const re of SECRET_RE) if (re.test(content)) hard.push(`possible secret token in ${f}`);
  }
  const lines = content.split(/\r?\n/);
  lines.forEach((line, i) => {
    for (const term of TERMS) {
      if (line.toLowerCase().includes(term.toLowerCase())) {
        soft.push({ term, file: f, line: i + 1, text: line.trim().slice(0, 120) });
      }
    }
  });
}

// must-fix = fake/placeholder terms in production paths, EXCLUDING honest status
// reporting (a runtime message that truthfully says "not configured / not
// implemented" is the opposite of faking success and is allowed).
const benign = /never (faked|fake)|no fake|not faked|honest|configured:\s*false|not_configured|reason:|status:\s*"not|is not implemented|provider not implemented/i;
const mustFix = soft.filter((s) => isProduction(s.file) && !benign.test(s.text));

// HARD: required docs + scripts exist
const requiredDocs = ["README.md", "docs/scanners.md", "docs/scanner-setup.md", "docs/model-providers.md", "docs/watch-mode.md", "docs/env-reference.md", "docs/known-limitations.md", "docs/final-feature-verification.md", "docs/submission-checklist.md"];
for (const d of requiredDocs) if (!existsSync(d)) hard.push(`missing required doc: ${d}`);
const pkg = JSON.parse(readFileSync("package.json", "utf8")) as { scripts: Record<string, string> };
const requiredScripts = ["typecheck", "lint", "test", "build", "audit:repo", "check:full", "check:unit", "verify:local-e2e", "demo:live"];
for (const s of requiredScripts) if (!pkg.scripts[s]) hard.push(`missing required script: ${s}`);

// SOFT: .env.example coverage of statically-referenced env keys
const example = existsSync(".env.example") ? readFileSync(".env.example", "utf8") : "";
const literals = new Set<string>();
for (const f of files) {
  if (!/^(packages\/core\/src|scripts)\//.test(f) || !/\.(ts|mjs)$/.test(f) || !existsSync(f)) continue;
  const m = readFileSync(f, "utf8").matchAll(/getEnv\("([A-Z][A-Z0-9_]+)"\)/g);
  for (const x of m) literals.add(x[1]!);
}
const missingEnv = [...literals].filter((k) => !new RegExp(`^${k}=`, "m").test(example) && !["NODE_ENV"].includes(k));

const ok = hard.length === 0 && mustFix.length === 0;
console.log(safeJson({
  ok,
  hardFailures: hard,
  mustFixProduction: mustFix,
  softTermCounts: TERMS.map((t) => ({ term: t, total: soft.filter((s) => s.term === t).length, inProduction: soft.filter((s) => s.term === t && isProduction(s.file)).length })).filter((x) => x.total > 0),
  envExampleMissingKeys: missingEnv,
  trackedFiles: files.length
}));
process.exit(ok ? 0 : 1);
