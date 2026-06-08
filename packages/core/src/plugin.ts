import crypto from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { z } from "zod";
import { RiskRadarError } from "./errors";
import { getEnv } from "./env";

export const pluginManifestSchema = z.object({
  id: z.string().min(3),
  version: z.string().min(1),
  entry: z.string().min(1),
  permissions: z.array(z.string()).default([])
});

export type PluginManifest = z.infer<typeof pluginManifestSchema>;

const DANGEROUS_PERMISSIONS = new Set(["filesystem:write", "network:any", "secrets:read", "process:exec"]);

export function validatePluginManifest(filePath: string): { manifest: PluginManifest; warnings: string[] } {
  if (!existsSync(filePath)) throw new RiskRadarError("plugin_manifest_missing", "Plugin manifest file does not exist.", { filePath });
  const manifest = pluginManifestSchema.parse(JSON.parse(readFileSync(filePath, "utf8")));
  const warnings = manifest.permissions.filter((permission) => DANGEROUS_PERMISSIONS.has(permission)).map((permission) => `Permission ${permission} requires explicit review.`);
  return { manifest, warnings };
}

// ---------- signed plugin registry ----------

/** Canonical (sorted-key) JSON of the validated manifest fields used for signing. */
function canonicalManifest(manifest: PluginManifest): string {
  return JSON.stringify({ id: manifest.id, version: manifest.version, entry: manifest.entry, permissions: [...manifest.permissions].sort() });
}

/** Signs a plugin manifest with the registry secret (HMAC-SHA256). */
export function signPluginManifest(manifest: PluginManifest, secret = getEnv("RISKRADAR_PLUGIN_SIGNING_SECRET")): string {
  if (!secret) throw new RiskRadarError("plugin_signing_secret_missing", "Set RISKRADAR_PLUGIN_SIGNING_SECRET to sign plugins.", { requiredEnv: "RISKRADAR_PLUGIN_SIGNING_SECRET" });
  return crypto.createHmac("sha256", secret).update(canonicalManifest(manifest)).digest("base64url");
}

/** Verifies a plugin manifest signature (constant-time). */
export function verifyPluginSignature(manifest: PluginManifest, signature: string, secret = getEnv("RISKRADAR_PLUGIN_SIGNING_SECRET")): boolean {
  if (!secret) return false;
  const expected = signPluginManifest(manifest, secret);
  const a = Buffer.from(signature);
  const b = Buffer.from(expected);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export interface PluginRegistryEntry { id: string; signature: string }

/**
 * Loads a plugin only if signing is enabled AND its signature is present in the
 * registry and valid. When signing is disabled (no secret), loads with a warning.
 */
export function loadSignedPlugin(filePath: string, registry: PluginRegistryEntry[], secret = getEnv("RISKRADAR_PLUGIN_SIGNING_SECRET")): { manifest: PluginManifest; warnings: string[]; signatureVerified: boolean } {
  const { manifest, warnings } = validatePluginManifest(filePath);
  if (!secret) {
    return { manifest, warnings: [...warnings, "Plugin signing disabled (RISKRADAR_PLUGIN_SIGNING_SECRET unset); signature not verified."], signatureVerified: false };
  }
  const entry = registry.find((item) => item.id === manifest.id);
  if (!entry) throw new RiskRadarError("plugin_unsigned", "Plugin is not in the signed registry.", { id: manifest.id });
  if (!verifyPluginSignature(manifest, entry.signature, secret)) {
    throw new RiskRadarError("plugin_signature_invalid", "Plugin signature does not match the signed registry.", { id: manifest.id });
  }
  return { manifest, warnings, signatureVerified: true };
}
