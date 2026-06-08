#!/usr/bin/env node
/**
 * Build docs/pitch-deck.pptx from docs/pitch-deck.html.
 *
 * Strategy: launch the system Chrome via puppeteer-core, scroll to each slide
 * at 1920x1080 (deviceScaleFactor 2 for crispness), screenshot, then embed the
 * four PNGs full-bleed into a 16:9 PowerPoint via pptxgenjs.
 *
 * Why this approach: it guarantees the .pptx looks EXACTLY like the HTML deck
 * (Cursor-Orange accent, Inter + JetBrains Mono, hairline borders, the pipeline,
 * the terminal proof). The slides aren't editable as text in PowerPoint - but
 * for hackathon submission and screen-share that's a feature, not a bug. The
 * authoritative editable source remains docs/pitch-deck.html.
 */
import { existsSync, renameSync, unlinkSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import puppeteer from "puppeteer-core";
import PptxGenJS from "pptxgenjs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const deckHtml = path.join(repoRoot, "docs", "pitch-deck.html");
const outFile = path.join(repoRoot, "docs", "pitch-deck.pptx");

const CHROME_CANDIDATES = [
  "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
  "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
  "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe"
];
const executablePath = CHROME_CANDIDATES.find(existsSync);
if (!executablePath) throw new Error("No system Chrome or Edge found. Install Chrome or set CHROME_BIN.");

const W = 1920;
const H = 1080;

console.log("[deck] launching", path.basename(executablePath));
const browser = await puppeteer.launch({
  executablePath,
  headless: "new",
  args: ["--no-sandbox", "--disable-dev-shm-usage", "--font-render-hinting=none"]
});

try {
  const page = await browser.newPage();
  // deviceScaleFactor 4 -> 7680x4320 physical pixels per slide (8K).
  // Maximum sharpness for slideshow rendering on any display.
  await page.setViewport({ width: W, height: H, deviceScaleFactor: 4 });
  await page.goto(pathToFileURL(deckHtml).href, { waitUntil: "networkidle0", timeout: 60_000 });
  // Wait for fonts to load and any initial animations to settle.
  await page.evaluateHandle("document.fonts.ready");
  await new Promise((r) => setTimeout(r, 800));

  const slideCount = await page.evaluate(() => document.querySelectorAll(".slide").length);
  console.log("[deck] slides found:", slideCount);
  // Measure each slide's actual content height vs the viewport so we can tell
  // when content overflows and the bottom would be clipped in the screenshot.
  const heights = await page.evaluate(() =>
    [...document.querySelectorAll(".slide")].map((s) => Math.ceil(s.scrollHeight))
  );
  console.log("[deck] slide content heights (viewport is " + H + "):", heights.join(", "));

  const buffers = [];
  for (let i = 0; i < slideCount; i++) {
    await page.evaluate((idx) => {
      const target = document.querySelectorAll(".slide")[idx];
      target.scrollIntoView({ behavior: "instant", block: "start" });
      // Force the IntersectionObserver-driven entry animation to land NOW.
      document.querySelectorAll(".slide").forEach((s, k) => s.classList.toggle("in-view", k === idx));
    }, i);
    // Allow the staggered entry transitions (up to ~1100ms) to finish.
    await new Promise((r) => setTimeout(r, 1400));
    const buf = await page.screenshot({
      clip: { x: 0, y: 0, width: W, height: H },
      type: "png"
    });
    buffers.push(buf);
    console.log(`[deck] captured slide ${i + 1}/${slideCount}`);
  }

  const pptx = new PptxGenJS();
  pptx.defineLayout({ name: "DECK_16x9", width: 13.333, height: 7.5 });
  pptx.layout = "DECK_16x9";
  pptx.title = "RiskRadar - Hackathon Pitch Deck (Phase 1)";
  pptx.author = "RiskRadar";
  pptx.company = "RiskRadar";

  // Speaker notes: real source URLs for the Slide 1 claims plus delivery cues
  // for the rest. These appear in PowerPoint's presenter view and are visible
  // to any reviewer who opens the .pptx in edit mode.
  const SPEAKER_NOTES = [
    [
      "SLIDE 1 - Sources for the claims on this slide:",
      "",
      "[npm supply-chain incidents, May 2026 - recent examples, sourced]",
      "- TanStack postmortem (May 11, 2026): https://tanstack.com/blog/npm-supply-chain-compromise-postmortem",
      "- Microsoft Security blog on @antv 'Mini Shai-Hulud' (May 20, 2026): https://www.microsoft.com/en-us/security/blog/2026/05/20/mini-shai-hulud-compromised-antv-npm-packages-enable-ci-cd-credential-theft/",
      "- StepSecurity on node-ipc (May 14, 2026): https://www.stepsecurity.io/blog/node-ipc-npm-supply-chain-attack",
      "- Wiz on TanStack + Mini Shai-Hulud wave: https://www.wiz.io/blog/mini-shai-hulud-strikes-again-tanstack-more-npm-packages-compromised",
      "",
      "[MCP attack-surface stats]",
      "- OX Security MCP STDIO advisory (April 2026, ~10 high/critical CVEs): https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem/",
      "- The Register on Anthropic MCP 'design flaw' & ~200,000 servers: https://www.theregister.com/2026/04/16/anthropic_mcp_design_flaw/",
      "- MCP-ITP research on tool-poisoning attack success rate (~84.2% ASR under auto-approve).",
      "",
      "Delivery cue: lead with the timeline; the audience should feel this is ongoing, not hypothetical."
    ].join("\n"),
    [
      "SLIDE 2 - Solution.",
      "",
      "Thesis: Codex writes the fix. RiskRadar's audited pipeline applies it. Only Codex (GPT-5.5) is permitted to mutate the repo - via the user's subscription, in a workspace-write sandbox.",
      "",
      "Failover (actual chain in providerChain.ts):",
      "1. Codex (the only model that writes to the repo)",
      "2. Configured cloud providers (OpenRouter / Anthropic / Grok / OpenAI-compatible) - cloud-to-cloud failover is automatic when enabled.",
      "3. Local Ollama - requires consent in 'ask' mode (Telegram tap) unless a per-repo always-allow policy exists.",
      "4. Deterministic (no-LLM) remediation as a final safe fallback.",
      "",
      "Non-Codex models only return strict-JSON plans; RiskRadar applies them. Raw secret findings are not sent to cloud models."
    ].join("\n"),
    [
      "SLIDE 3 - Stack. Delivery cue: do not read the whole grid.",
      "",
      "One line is enough: 'Everything here is wired or honestly marked missing. Codex live, scanners real, 110 tests pass.' Then advance.",
      "",
      "Proof points if asked:",
      "- 110 Vitest tests passing (reachability + attestation + scanners + provider chain).",
      "- verify:codex-live confirmed end-to-end with codexStatus:completed and pr_ready.",
      "- Repo self-audit (audit:repo) returns ok:true, no hard failures.",
      "- Missing tools surface as tool_missing / not_configured - no fake green."
    ].join("\n"),
    [
      "SLIDE 4 - ICP.",
      "",
      "Primary wedge: AI-era builders + small teams without a security person.",
      "They ship code generated by Cursor, Claude Code, Codex Desktop, Replit Agent 3, Devin, v0, Lovable, Bolt, Copilot.",
      "They don't read the dependency tree and can't maintain what they ship; RiskRadar is the safety net.",
      "",
      "Buyer/user split: developer / AI-assisted builder / platform engineer use it; the founder / eng lead / CTO buys it because it has an audit trail and the no-auto-merge / no-data-leak guarantee.",
      "",
      "Closing tagline: 'Your repos and your AI agents. One command center.'"
    ].join("\n")
  ];

  for (let i = 0; i < buffers.length; i++) {
    const slide = pptx.addSlide();
    slide.background = { color: "0D0D0C" };
    slide.addImage({
      data: "image/png;base64," + buffers[i].toString("base64"),
      x: 0,
      y: 0,
      w: 13.333,
      h: 7.5
    });
    if (SPEAKER_NOTES[i]) slide.addNotes(SPEAKER_NOTES[i]);
  }

  // Write to a temp filename first, then swap into place. This avoids EBUSY
  // when the user has the .pptx open in PowerPoint / WPS during regeneration.
  const tmpFile = outFile.replace(/\.pptx$/i, ".new.pptx");
  if (existsSync(tmpFile)) unlinkSync(tmpFile);
  await pptx.writeFile({ fileName: tmpFile });
  try {
    renameSync(tmpFile, outFile);
    console.log("[deck] wrote", outFile);
  } catch (err) {
    if (err && (err.code === "EBUSY" || err.code === "EPERM")) {
      console.log("[deck] target file is locked (open in PowerPoint?). Wrote alongside as:", tmpFile);
      console.log("[deck] close the viewer and rename .new.pptx -> .pptx, or rerun this script.");
    } else {
      throw err;
    }
  }
} finally {
  await browser.close();
}
