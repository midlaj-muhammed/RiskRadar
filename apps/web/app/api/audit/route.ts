import { NextResponse } from "next/server";
import { JsonDatabase } from "@riskradar/core";

export function GET() {
  return NextResponse.json({ receipts: new JsonDatabase().read().auditReceipts });
}
