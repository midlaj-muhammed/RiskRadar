import { existsSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { JsonDatabase, emptyState, hydrateFromPostgres, loadStateFromPostgres, postgresStatus, saveStateToPostgres } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();
// Default to the docker-compose container if not already configured.
process.env.RISKRADAR_PERSIST_POSTGRES ||= "true";
process.env.DATABASE_URL ||= "postgresql://riskradar:riskradar@localhost:5432/riskradar";

// Proves durable persistence: (1) round-trip a state document through Postgres,
// and (2) hydrate a fresh local file from Postgres after the file is deleted.
async function main() {
  const marker = `proj_pgtest_${Date.now()}`;
  const sample = { ...emptyState(), projects: [{ id: marker, name: "pg-roundtrip", sourceType: "local", isPathAllowlisted: true, packageManager: "npm", deploymentProvider: "none", productionExposed: false, createdAt: new Date().toISOString(), updatedAt: new Date().toISOString() }] } as ReturnType<typeof emptyState>;
  await saveStateToPostgres(sample);
  const loaded = await loadStateFromPostgres();
  const status = await postgresStatus();
  const roundTrip = loaded?.projects?.[0]?.id === marker;

  // Cross-process durability: a brand-new local file hydrates from Postgres.
  const freshFile = path.join(os.tmpdir(), `riskradar-pg-hydrate-${Date.now()}.json`);
  const freshDb = new JsonDatabase(freshFile);
  const hydrated = await hydrateFromPostgres(freshDb);
  const restored = freshDb.read().projects.some((p) => p.id === marker);
  if (existsSync(freshFile)) rmSync(freshFile, { force: true });

  const ok = status.ok && roundTrip && hydrated && restored;
  console.log(safeJson({ ok, status, roundTrip, hydratedFromPostgres: hydrated, fileRestoredFromPostgres: restored, projectsInPostgres: loaded?.projects?.length ?? 0 }));
  if (!ok) process.exit(1);
  process.exit(0);
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
