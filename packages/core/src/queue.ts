import { getEnv } from "./env";

/**
 * Durable job queue + scheduler backed by Redis/BullMQ (opt-in). Enabled only
 * when RISKRADAR_QUEUE_MODE=redis AND REDIS_URL is set; otherwise RiskRadar
 * uses its existing inline execution (default), so tests/demos are unaffected.
 *
 * The queue survives process restarts (jobs + repeatable watch schedule live in
 * Redis), which is the durable-scheduler the file-only inline mode lacked.
 */
export const QUEUE_NAME = "riskradar";

export type QueueJob =
  | { type: "ping" }
  | { type: "scan"; projectId: string }
  | { type: "scan-all" }
  | { type: "remediate"; findingId: string }
  | { type: "watch-cycle" };

export function queueEnabled(): boolean {
  return getEnv("RISKRADAR_QUEUE_MODE") === "redis" && Boolean(getEnv("REDIS_URL"));
}

function connection(): { host: string; port: number } {
  const url = new URL(getEnv("REDIS_URL") ?? "redis://localhost:6379");
  return { host: url.hostname, port: Number(url.port || 6379) };
}

// bullmq is imported lazily so the dependency never loads on the default path.
async function bull() {
  return import("bullmq");
}

let queueInstance: { add: (name: string, data: QueueJob, opts?: unknown) => Promise<{ id?: string }>; getJobCounts: () => Promise<Record<string, number>>; close: () => Promise<void> } | undefined;

async function getQueue() {
  if (!queueInstance) {
    const { Queue } = await bull();
    queueInstance = new Queue(QUEUE_NAME, { connection: connection() }) as never;
  }
  return queueInstance!;
}

export async function enqueue(job: QueueJob): Promise<string | undefined> {
  if (!queueEnabled()) throw new Error("Queue mode is not enabled (set RISKRADAR_QUEUE_MODE=redis + REDIS_URL).");
  const queue = await getQueue();
  const added = await queue.add(job.type, job, { removeOnComplete: 100, removeOnFail: 100 });
  return added.id;
}

/** Schedules a durable repeatable watch cycle (survives restarts). */
export async function scheduleWatchCycle(intervalMinutes: number): Promise<void> {
  const queue = await getQueue();
  await queue.add("watch-cycle", { type: "watch-cycle" }, { repeat: { every: Math.max(1, intervalMinutes) * 60_000 }, jobId: "watch-cycle" });
}

export async function queueStatus(): Promise<{ enabled: boolean; counts?: Record<string, number>; message: string }> {
  if (!queueEnabled()) return { enabled: false, message: "Inline mode (set RISKRADAR_QUEUE_MODE=redis + REDIS_URL for the durable queue)." };
  try {
    const queue = await getQueue();
    return { enabled: true, counts: await queue.getJobCounts(), message: "Redis queue reachable." };
  } catch (error) {
    return { enabled: true, message: `Redis error: ${error instanceof Error ? error.message : String(error)}` };
  }
}

export interface QueueProcessors {
  scan: (projectId: string) => Promise<unknown>;
  scanAll: () => Promise<unknown>;
  remediate: (findingId: string) => Promise<unknown>;
  watchCycle: () => Promise<unknown>;
}

/**
 * Starts a BullMQ worker that processes jobs via the provided service callbacks.
 * Returns the worker (call .close() to stop). No-op-safe: throws clearly if the
 * queue is not enabled.
 */
export async function startQueueWorker(processors: QueueProcessors): Promise<{ close: () => Promise<void> }> {
  if (!queueEnabled()) throw new Error("Queue mode is not enabled.");
  const { Worker } = await bull();
  const worker = new Worker(
    QUEUE_NAME,
    async (job: { name: string; data: QueueJob }) => {
      const data = job.data;
      switch (data.type) {
        case "ping": return { ok: true };
        case "scan": return processors.scan(data.projectId);
        case "scan-all": return processors.scanAll();
        case "remediate": return processors.remediate(data.findingId);
        case "watch-cycle": return processors.watchCycle();
        default: return { ignored: true };
      }
    },
    { connection: connection() }
  );
  return worker as unknown as { close: () => Promise<void> };
}
