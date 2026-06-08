import { JsonDatabase, dataFilePath, postgresEnabled, postgresStatus, queueStatus } from "../packages/core/src/index.ts";
import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();

// Shows the durable-persistence + queue status (no secrets).
async function main() {
  const state = new JsonDatabase().read();
  console.log(safeJson({
    ok: true,
    dataFile: dataFilePath(),
    localCounts: {
      projects: state.projects.length,
      findings: state.findings.length,
      remediationJobs: state.remediationJobs.length,
      auditReceipts: state.auditReceipts.length
    },
    postgres: { enabled: postgresEnabled(), ...(await postgresStatus()) },
    queue: await queueStatus()
  }));
  process.exit(0);
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
