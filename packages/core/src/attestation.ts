import crypto from "node:crypto";
import { getEnv } from "./env";

/**
 * Provenance attestation for a remediation.
 *
 * When RiskRadar upgrades a vulnerable dependency, it produces a signed,
 * verifiable statement of WHAT changed and HOW it was validated — in the spirit
 * of SLSA provenance / in-toto attestations, but lightweight (HMAC, no PKI).
 * The statement is canonicalized (stable key order) before signing so the
 * signature is reproducible and tamper-evident. The signed line goes into the
 * PR body and the audit receipt, so a reviewer can confirm the fix's origin.
 */
export interface AttestationStatement {
  predicateType: "https://riskradar.dev/attestation/remediation/v1";
  package: string;
  ecosystem: string;
  fromVersion: string;
  toVersion: string;
  fixStrategy: string;
  validation: "passed" | "failed" | "skipped" | "not_run";
  vulnerabilityIds: string[];
  changedFiles: string[];
  remediationJobId: string;
  builder: "riskradar";
  agent: string;
  timestamp: string;
}

export interface SignedAttestation {
  statement: AttestationStatement;
  signature: string | null;
  signed: boolean;
  algorithm: "HMAC-SHA256";
  keyId: "RISKRADAR_ATTESTATION_SECRET" | "APPROVAL_HMAC_SECRET" | null;
}

/** Deterministically serialize an object with sorted keys so signing is stable. */
function canonicalize(value: unknown): string {
  if (Array.isArray(value)) return `[${value.map(canonicalize).join(",")}]`;
  if (value && typeof value === "object") {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([, v]) => v !== undefined)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${JSON.stringify(k)}:${canonicalize(v)}`);
    return `{${entries.join(",")}}`;
  }
  return JSON.stringify(value ?? null);
}

function resolveSecret(): { secret: string; keyId: SignedAttestation["keyId"] } | null {
  const dedicated = getEnv("RISKRADAR_ATTESTATION_SECRET");
  if (dedicated) return { secret: dedicated, keyId: "RISKRADAR_ATTESTATION_SECRET" };
  const shared = getEnv("APPROVAL_HMAC_SECRET");
  if (shared) return { secret: shared, keyId: "APPROVAL_HMAC_SECRET" };
  return null;
}

export interface AttestRemediationInput {
  package: string;
  ecosystem: string;
  fromVersion: string;
  toVersion: string;
  fixStrategy?: string;
  validation?: AttestationStatement["validation"];
  vulnerabilityIds?: string[];
  changedFiles?: string[];
  remediationJobId: string;
  agent?: string;
  timestamp?: string;
}

/**
 * Builds the canonical statement and signs it (HMAC). If no secret is
 * configured, returns the statement unsigned (honest: signed=false) rather
 * than fabricating a signature.
 */
export function attestRemediation(input: AttestRemediationInput): SignedAttestation {
  const statement: AttestationStatement = {
    predicateType: "https://riskradar.dev/attestation/remediation/v1",
    package: input.package,
    ecosystem: input.ecosystem,
    fromVersion: input.fromVersion,
    toVersion: input.toVersion,
    fixStrategy: input.fixStrategy ?? "safe_patch",
    validation: input.validation ?? "not_run",
    vulnerabilityIds: input.vulnerabilityIds ?? [],
    changedFiles: input.changedFiles ?? [],
    remediationJobId: input.remediationJobId,
    builder: "riskradar",
    agent: input.agent ?? "deterministic",
    timestamp: input.timestamp ?? new Date().toISOString()
  };
  const resolved = resolveSecret();
  if (!resolved) {
    return { statement, signature: null, signed: false, algorithm: "HMAC-SHA256", keyId: null };
  }
  const signature = crypto.createHmac("sha256", resolved.secret).update(canonicalize(statement)).digest("base64url");
  return { statement, signature, signed: true, algorithm: "HMAC-SHA256", keyId: resolved.keyId };
}

/** Recomputes the signature and compares in constant time. */
export function verifyAttestation(statement: AttestationStatement, signature: string): boolean {
  const resolved = resolveSecret();
  if (!resolved || !signature) return false;
  const expected = crypto.createHmac("sha256", resolved.secret).update(canonicalize(statement)).digest("base64url");
  if (expected.length !== signature.length) return false;
  return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(expected));
}

/** One-line, human-readable attestation for a PR body or chat message. */
export function attestationLine(att: SignedAttestation): string {
  const s = att.statement;
  const provenance = `${s.package} ${s.fromVersion} → ${s.toVersion} (${s.ecosystem}, validation: ${s.validation}, by ${s.agent})`;
  if (att.signed && att.signature) {
    return `🔏 Provenance attestation (HMAC-SHA256, key ${att.keyId}): ${provenance} · sig ${att.signature.slice(0, 16)}…`;
  }
  return `🔏 Provenance attestation (unsigned — set RISKRADAR_ATTESTATION_SECRET to sign): ${provenance}`;
}
