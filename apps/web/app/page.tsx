import {
  ArrowRight, Github, ShieldCheck, GitPullRequest, Target, Boxes,
  FileSignature, Smartphone, Terminal, ScanLine, Radar
} from "lucide-react";
import { CopyCommand } from "../components/CopyCommand";

const REPO = "https://github.com/midlaj-muhammed/RiskRadar.git";

const PIPELINE = [
  ["01", "Inventory"], ["02", "Scan"], ["03", "Reachability"], ["04", "Risk"],
  ["05", "Codex writes"], ["06", "Validate"], ["07", "Attest"], ["08", "Approve"], ["09", "Audit"]
] as const;
const HOT = new Set([2, 4, 6]);

const FEATURES = [
  [Target, "Reachability / VEX-lite", "Is the vulnerable package actually imported in your source? If not, it's de-prioritized. The CVE wall shrinks to the handful that matter."],
  [Boxes, "Connect any model", "Codex (GPT-5.5) is the only model that writes to the repo. Behind it, configured cloud or local providers by policy, then a deterministic fallback. Secrets never reach the cloud."],
  [FileSignature, "Signed attestation", "Every fix ships a verifiable HMAC statement of from→to, validation result, and files changed, embedded in the pull request."],
  [Smartphone, "Human-in-the-loop", "Inline Telegram buttons to approve, reject, retry safer, or rollback. No auto-merge, no auto-deploy, no exceptions."]
] as const;

const STACK = [
  "OpenAI Codex · GPT-5.5", "Ollama · local", "OpenRouter · any model", "OSV + OSV-Scanner",
  "Gitleaks", "Trivy", "Syft · SBOM", "EPSS", "CISA KEV", "MCP server",
  "Telegram · HMAC", "Postgres 16", "Redis · BullMQ", "Next.js 16", "TypeScript"
];

export default function Landing() {
  return (
    <div className="lp">
      <div className="lp-glow" aria-hidden="true" />
      <header className="lp-nav">
        <a className="lp-brand" href="/"><span className="lp-dot" />RiskRadar</a>
        <nav className="lp-nav-links">
          <a href="#how">How it works</a>
          <a href="#features">Features</a>
          <a href={REPO} target="_blank" rel="noreferrer">GitHub</a>
          <a className="lp-btn lp-btn-sm" href="/dashboard">Open dashboard <ArrowRight size={15} /></a>
        </nav>
      </header>

      {/* ===== Hero ===== */}
      <section className="lp-hero">
        <div className="lp-hero-copy">
          <span className="lp-eyebrow">Watch Commander · supply-chain security</span>
          <h1 className="lp-h1">
            <span className="sentence">The model <em>plans</em> the fix.</span>
            <span className="sentence"><span className="nowrap">A <span className="lp-accent">signed, human-approved</span></span> pipeline applies it.</span>
          </h1>
          <p className="lp-lede">
            RiskRadar finds the CVEs that actually reach your code, lets OpenAI Codex write the fix
            in a sandbox, signs the result, and waits for a tap on your phone. Every integration runs
            live (Codex, OSV, GitHub, Telegram) with a full audit trail behind each change.
          </p>
          <div className="lp-cta">
            <a className="lp-btn" href="/dashboard">Open the dashboard <ArrowRight size={16} /></a>
            <a className="lp-btn lp-btn-ghost" href={REPO} target="_blank" rel="noreferrer"><Github size={16} /> View on GitHub</a>
          </div>
          <CopyCommand label="Scan your own project" command="npx riskradar-cli scan" />
          <div className="lp-trust">
            <span><ShieldCheck size={14} /> No auto-merge, no auto-deploy</span>
            <span><GitPullRequest size={14} /> Signed provenance on every fix</span>
          </div>
        </div>

        <div className="lp-terminal" aria-hidden="true">
          <div className="lp-term-bar">
            <span className="lp-term-lights"><i /><i /><i /></span>
            <span className="lp-term-title">riskradar · scan</span>
          </div>
          <div className="lp-term-body">
            <div className="t-line"><span className="t-mut">$</span> npx riskradar-cli scan ./storefront</div>
            <div className="t-line t-dim">Scanning 318 deps via OSV…</div>
            <div className="t-line">&nbsp;</div>
            <div className="t-line"><span className="t-red">CRIT</span>{"  "}<span className="t-b">lodash</span><span className="t-dim">@4.17.11</span>{"   "}<span className="t-grn">→ 4.17.21</span></div>
            <div className="t-line t-dim">{"      "}<span className="t-acc">● reachable</span> · GHSA-jf85</div>
            <div className="t-line"><span className="t-yel">HIGH</span>{"  "}<span className="t-b">axios</span><span className="t-dim">@1.4.0</span>{"      "}<span className="t-grn">→ 1.6.2</span></div>
            <div className="t-line t-dim">{"      "}<span className="t-acc">● reachable</span> · GHSA-wf5p</div>
            <div className="t-line t-dim">LOW{"   "}color-convert{"    "}○ likely unused</div>
            <div className="t-line t-dim">MED{"   "}minimist{"         "}○ transitive</div>
            <div className="t-line">&nbsp;</div>
            <div className="t-line"><span className="t-acc">▸</span> <span className="t-b">2 reachable</span> <span className="t-dim">· 2 de-prioritized</span></div>
            <div className="t-line t-dim">{"  "}Fix the reachable ones first.</div>
          </div>
        </div>
      </section>

      {/* ===== How it works ===== */}
      <section className="lp-section" id="how">
        <span className="lp-section-label"><Radar size={13} /> How it works</span>
        <h2 className="lp-h2">Nine steps from a CVE to a signed, approved fix.</h2>
        <div className="lp-pipeline">
          {PIPELINE.map(([n, name], i) => (
            <div className={`lp-step${HOT.has(i) ? " hot" : ""}`} key={n}>
              <span className="lp-step-n">{n}</span>
              <span className="lp-step-name">{name}</span>
            </div>
          ))}
        </div>
        <p className="lp-note">Highlighted steps are RiskRadar's edge: <span className="lp-accent">reachability triage</span>, <span className="lp-accent">Codex-written fixes</span>, and a <span className="lp-accent">signed attestation</span>, all gated behind a human tap.</p>
      </section>

      {/* ===== Features ===== */}
      <section className="lp-section" id="features">
        <span className="lp-section-label"><ScanLine size={13} /> What makes it different</span>
        <h2 className="lp-h2">Triage what's reachable. Fix it safely. Prove it with a signature.</h2>
        <div className="lp-features">
          {FEATURES.map(([Icon, title, body]) => (
            <div className="lp-feature" key={title as string}>
              <span className="lp-feature-ic"><Icon size={18} /></span>
              <h3>{title as string}</h3>
              <p>{body as string}</p>
            </div>
          ))}
        </div>
      </section>

      {/* ===== Stack ===== */}
      <section className="lp-section">
        <span className="lp-section-label"><Terminal size={13} /> Integrated with the tools you already trust</span>
        <div className="lp-stack">
          {STACK.map((s) => <span className="lp-chip" key={s}>{s}</span>)}
        </div>
      </section>

      {/* ===== Final CTA ===== */}
      <section className="lp-final">
        <h2 className="lp-final-h">Your repos and your AI agents.<br /><span className="lp-accent">One command center.</span></h2>
        <div className="lp-cta">
          <a className="lp-btn" href="/dashboard">Open the dashboard <ArrowRight size={16} /></a>
          <a className="lp-btn lp-btn-ghost" href={REPO} target="_blank" rel="noreferrer"><Github size={16} /> Star on GitHub</a>
        </div>
      </section>

      <footer className="lp-foot">
        <span className="lp-brand"><span className="lp-dot" />RiskRadar</span>
        <span className="lp-mono">Open-source · CVE &amp; supply-chain response · built with OpenAI Codex</span>
      </footer>
    </div>
  );
}
