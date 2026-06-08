#!/usr/bin/env node
/**
 * One-command hosted demo deploy.
 *
 *   pnpm deploy:demo
 *
 * Deploys apps/web to Vercel production with the demo env (seeded data + banner),
 * then re-points the stable alias (tryriskradar.vercel.app) at the new
 * deployment — so the custom domain always follows the latest production build.
 */
import { execSync } from "node:child_process";

const SCOPE = process.env.VERCEL_SCOPE ?? "aibots-projects-bfdd3c0c";
const ALIAS = process.env.RISKRADAR_DEMO_ALIAS ?? "tryriskradar.vercel.app";
const ENV = ["RISKRADAR_DEMO=true", "RISKRADAR_DATA_FILE=demo/seed.json"];

const envFlags = ENV.flatMap((e) => ["--build-env", e, "--env", e]).join(" ");
const cmd = `vercel deploy --prod --yes --scope ${SCOPE} ${envFlags}`;

console.log(`[deploy] ${cmd}`);
const out = execSync(cmd, { encoding: "utf8", stdio: ["inherit", "pipe", "inherit"] });
process.stdout.write(out);

const url = (out.match(/https:\/\/[a-z0-9-]+\.vercel\.app/gi) ?? []).pop();
if (!url) {
  console.error("[deploy] Could not parse deployment URL from output; alias not updated.");
  process.exit(1);
}
console.log(`[deploy] production deployment: ${url}`);
execSync(`vercel alias set ${url} ${ALIAS} --scope ${SCOPE}`, { stdio: "inherit" });
console.log(`[deploy] ✓ ${ALIAS} now points at the latest production deployment.`);
