import { getEnv } from "./env";
import type { RiskRadarState } from "./types";

/**
 * Postgres durable persistence (opt-in). RiskRadar's store is synchronous and
 * file-backed; rather than a risky async rewrite, Postgres acts as the durable
 * system of record: every write is mirrored into a single JSONB document, and
 * the local file can be hydrated from Postgres on startup. Enabled only when
 * RISKRADAR_PERSIST_POSTGRES=true AND DATABASE_URL is set, so the default
 * file-only path (and all tests/demos) are unaffected.
 */
export function postgresEnabled(): boolean {
  return getEnv("RISKRADAR_PERSIST_POSTGRES") === "true" && Boolean(getEnv("DATABASE_URL"));
}

// pg is imported lazily so the dependency is never loaded on the default path.
type PgPool = { query: (text: string, params?: unknown[]) => Promise<{ rows: Array<{ doc: RiskRadarState }> }>; end: () => Promise<void> };
let poolPromise: Promise<PgPool> | undefined;

async function getPool(): Promise<PgPool> {
  if (!poolPromise) {
    poolPromise = (async () => {
      const { Pool } = await import("pg");
      const pool = new Pool({ connectionString: getEnv("DATABASE_URL"), max: 4, connectionTimeoutMillis: 5000 }) as unknown as PgPool;
      await pool.query("CREATE TABLE IF NOT EXISTS riskradar_state (id INT PRIMARY KEY, doc JSONB NOT NULL, updated_at TIMESTAMPTZ NOT NULL DEFAULT now())");
      return pool;
    })();
  }
  return poolPromise;
}

export async function saveStateToPostgres(state: RiskRadarState): Promise<void> {
  const pool = await getPool();
  await pool.query(
    "INSERT INTO riskradar_state (id, doc, updated_at) VALUES (1, $1, now()) ON CONFLICT (id) DO UPDATE SET doc = EXCLUDED.doc, updated_at = now()",
    [JSON.stringify(state)]
  );
}

export async function loadStateFromPostgres(): Promise<RiskRadarState | undefined> {
  const pool = await getPool();
  const result = await pool.query("SELECT doc FROM riskradar_state WHERE id = 1");
  return result.rows[0]?.doc;
}

export async function postgresStatus(): Promise<{ ok: boolean; hasState: boolean; message: string }> {
  if (!postgresEnabled()) return { ok: false, hasState: false, message: "Postgres persistence disabled (set RISKRADAR_PERSIST_POSTGRES=true + DATABASE_URL)." };
  try {
    const pool = await getPool();
    const result = await pool.query("SELECT doc FROM riskradar_state WHERE id = 1");
    return { ok: true, hasState: result.rows.length > 0, message: "Postgres reachable; schema ready." };
  } catch (error) {
    return { ok: false, hasState: false, message: `Postgres error: ${error instanceof Error ? error.message : String(error)}` };
  }
}

/** Best-effort async mirror used as a write hook. Never throws into the caller. */
export function mirrorStateToPostgres(state: RiskRadarState): void {
  if (!postgresEnabled()) return;
  void saveStateToPostgres(state).catch((error) => {
    // Durability is best-effort from the synchronous write path.
    console.error(`[riskradar] postgres mirror failed: ${error instanceof Error ? error.message : String(error)}`);
  });
}
