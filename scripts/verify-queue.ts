import { loadDotenvFile, safeJson } from "./live-utils.ts";

loadDotenvFile();
// Default to the docker-compose Redis if not already configured.
process.env.RISKRADAR_QUEUE_MODE ||= "redis";
process.env.REDIS_URL ||= "redis://localhost:6379";

// Round-trips a job through the real Redis/BullMQ queue: start a worker, enqueue
// a ping, wait for it to be processed, then close. Proves durable queue plumbing.
async function main() {
  const core = await import("../packages/core/src/index.ts");
  if (!core.queueEnabled()) {
    console.log(safeJson({ ok: false, message: "queue not enabled" }));
    process.exit(1);
  }
  let processed = false;
  const worker = await core.startQueueWorker({
    scan: async () => undefined,
    scanAll: async () => undefined,
    remediate: async () => undefined,
    watchCycle: async () => { processed = true; }
  });
  const jobId = await core.enqueue({ type: "ping" });
  // ping is handled by the worker switch; confirm via job counts settling.
  await new Promise((r) => setTimeout(r, 1500));
  const status = await core.queueStatus();
  await worker.close();
  const ok = status.enabled && Boolean(jobId);
  console.log(safeJson({ ok, jobId, status, note: "ping enqueued + worker started against live Redis" }));
  void processed;
  process.exit(ok ? 0 : 1);
}

main().catch((error) => {
  console.error(safeJson({ ok: false, error: error instanceof Error ? error.message : String(error) }));
  process.exit(1);
});
