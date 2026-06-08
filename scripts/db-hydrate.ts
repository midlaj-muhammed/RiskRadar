import { JsonDatabase, hydrateFromPostgres, postgresEnabled } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Rebuilds the local state file from the Postgres durable store of record.
async function main() {
  if (!postgresEnabled()) {
    console.log(safeJson({ ok: false, message: "Postgres persistence disabled (set RISKRADAR_PERSIST_POSTGRES=true + DATABASE_URL)." }));
    process.exit(1);
  }
  const db = new JsonDatabase();
  const hydrated = await hydrateFromPostgres(db);
  const state = db.read();
  console.log(safeJson({ ok: hydrated, hydrated, projects: state.projects.length, findings: state.findings.length, message: hydrated ? "Local state rebuilt from Postgres." : "No state document in Postgres yet." }));
  process.exit(0);
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
