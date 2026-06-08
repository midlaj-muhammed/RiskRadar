import crypto from "node:crypto";
import { RiskRadarError } from "./errors";
import { getEnv } from "./env";

function base64url(input: string | Buffer): string {
  return Buffer.from(input).toString("base64url");
}

export interface ApprovalPayload {
  approvalId: string;
  action:
    | "approve"
    | "reject"
    | "review"
    | "retry_safer_fix"
    | "rollback"
    // provider-failover consent actions
    | "allow_once"
    | "always_allow_repo"
    | "use_deterministic";
  exp: number;
}

export function signApprovalPayload(payload: ApprovalPayload, secret = getEnv("APPROVAL_HMAC_SECRET")): string {
  if (!secret) throw new RiskRadarError("approval_secret_missing", "Set APPROVAL_HMAC_SECRET to sign approval callbacks.");
  const encoded = base64url(JSON.stringify(payload));
  const sig = crypto.createHmac("sha256", secret).update(encoded).digest("base64url");
  return `${encoded}.${sig}`;
}

export function verifyApprovalToken(token: string, secret = getEnv("APPROVAL_HMAC_SECRET"), nowSeconds = Math.floor(Date.now() / 1000)): ApprovalPayload {
  if (!secret) throw new RiskRadarError("approval_secret_missing", "Set APPROVAL_HMAC_SECRET to verify approval callbacks.");
  const [encoded, sig] = token.split(".");
  if (!encoded || !sig) throw new RiskRadarError("approval_signature_invalid", "Approval callback signature is malformed.");
  const expected = crypto.createHmac("sha256", secret).update(encoded).digest("base64url");
  if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
    throw new RiskRadarError("approval_signature_invalid", "Approval callback signature is invalid.");
  }
  const payload = JSON.parse(Buffer.from(encoded, "base64url").toString("utf8")) as ApprovalPayload;
  if (payload.exp < nowSeconds) throw new RiskRadarError("approval_token_expired", "Approval callback token has expired.");
  return payload;
}

export function chatAllowed(chatId: string | number): boolean {
  const allowed = (getEnv("TELEGRAM_ALLOWED_CHAT_IDS") ?? "").split(",").map((value) => value.trim()).filter(Boolean);
  return allowed.includes(String(chatId));
}

export function hashChatId(chatId: string | number): string {
  return crypto.createHash("sha256").update(String(chatId)).digest("hex");
}
