#!/usr/bin/env node
// Downloads official Windows release binaries for the external scanners into a
// gitignored .tools/ directory (no admin / winget prompts). Prints the resolved
// paths so they can be set as RISKRADAR_SCANNER_*_PATH.
import { execSync } from "node:child_process";
import { existsSync, mkdirSync, writeFileSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const TOOLS = path.resolve(".tools");
mkdirSync(TOOLS, { recursive: true });

const token = existsSync(".env") ? (readFileSync(".env", "utf8").match(/^GITHUB_TOKEN=(.+)$/m) || [])[1]?.trim() : undefined;

const targets = [
  { id: "gitleaks", repo: "gitleaks/gitleaks", match: /windows_x64\.zip$/, exe: "gitleaks.exe" },
  { id: "trivy", repo: "aquasecurity/trivy", match: /windows-64bit\.zip$/, exe: "trivy.exe" },
  { id: "syft", repo: "anchore/syft", match: /windows_amd64\.zip$/, exe: "syft.exe" },
  { id: "osv-scanner", repo: "google/osv-scanner", match: /windows_amd64\.exe$/, exe: "osv-scanner.exe", single: true }
];

async function ghJson(url) {
  const res = await fetch(url, { headers: { accept: "application/vnd.github+json", ...(token ? { authorization: `Bearer ${token}` } : {}) } });
  if (!res.ok) throw new Error(`GitHub API ${res.status} for ${url}`);
  return res.json();
}

async function download(url, dest) {
  const res = await fetch(url, { redirect: "follow", headers: token ? { authorization: `Bearer ${token}` } : {} });
  if (!res.ok) throw new Error(`download ${res.status} ${url}`);
  const buf = Buffer.from(await res.arrayBuffer());
  writeFileSync(dest, buf);
}

const results = [];
for (const t of targets) {
  const outExe = path.join(TOOLS, t.exe);
  try {
    if (existsSync(outExe)) { results.push({ id: t.id, status: "already-present", path: outExe }); continue; }
    const rel = await ghJson(`https://api.github.com/repos/${t.repo}/releases/latest`);
    const asset = (rel.assets || []).find((a) => t.match.test(a.name));
    if (!asset) { results.push({ id: t.id, status: "no-windows-asset", tag: rel.tag_name }); continue; }
    if (t.single) {
      await download(asset.browser_download_url, outExe);
    } else {
      const zip = path.join(TOOLS, `${t.id}.zip`);
      await download(asset.browser_download_url, zip);
      // Use PowerShell Expand-Archive (Git Bash's GNU tar can't read zips).
      execSync(`powershell -NoProfile -Command "Expand-Archive -Path '${zip}' -DestinationPath '${TOOLS}' -Force"`, { stdio: "ignore" });
    }
    results.push({ id: t.id, status: existsSync(outExe) ? "installed" : "extracted-check", path: outExe, files: readdirSync(TOOLS).filter((f) => f.startsWith(t.id) || f === t.exe) });
  } catch (error) {
    results.push({ id: t.id, status: "error", error: error instanceof Error ? error.message : String(error) });
  }
}

console.log(JSON.stringify({ toolsDir: TOOLS, results }, null, 2));
