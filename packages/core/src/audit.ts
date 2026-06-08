import crypto from "node:crypto";
import { id, now, type JsonDatabase } from "./database";
import { redactObject } from "./redaction";
import type { AuditReceipt } from "./types";

export function hashReceipt(receipt: Omit<AuditReceipt, "receiptHash">): string {
  return crypto.createHash("sha256").update(JSON.stringify(receipt)).digest("hex");
}

export function createAuditReceipt(
  db: JsonDatabase,
  input: Omit<AuditReceipt, "id" | "createdAt" | "receiptHash" | "previousReceiptHash" | "redacted" | "changedFiles"> & {
    changedFiles?: string[];
    redacted?: boolean;
  }
): AuditReceipt {
  let created!: AuditReceipt;
  db.update((state) => {
    const previous = state.auditReceipts.at(-1);
    const base: Omit<AuditReceipt, "receiptHash"> = {
      id: id("rec"),
      createdAt: now(),
      previousReceiptHash: previous?.receiptHash,
      changedFiles: input.changedFiles ?? [],
      redacted: input.redacted ?? true,
      ...redactObject(input)
    };
    created = { ...base, receiptHash: hashReceipt(base) };
    state.auditReceipts.push(created);
  });
  return created;
}
