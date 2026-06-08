import path from "node:path";
import { fileURLToPath } from "node:url";

const here = path.dirname(fileURLToPath(import.meta.url));
const monorepoRoot = path.join(here, "..", "..");

const nextConfig = {
  transpilePackages: ["@riskradar/core"],
  // The dashboard pages render dynamically and read the demo seed from disk at
  // request time (RISKRADAR_DEMO). On serverless those files aren't traced
  // automatically because nothing imports them, so bundle the seed + the
  // workspace marker (repoRoot() looks for pnpm-workspace.yaml) into every
  // function. Tracing root = monorepo root so the relative layout is preserved.
  outputFileTracingRoot: monorepoRoot,
  outputFileTracingIncludes: {
    "/**": ["../../demo/seed.json", "../../pnpm-workspace.yaml"]
  },
  generateBuildId: async () => process.env.NEXT_BUILD_ID ?? `riskradar-${Date.now()}`
};

export default nextConfig;
