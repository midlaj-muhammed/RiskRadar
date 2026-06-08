import { NextResponse } from "next/server";
import { JsonDatabase } from "@riskradar/core";

export function GET() {
  return NextResponse.json({ approvals: new JsonDatabase().read().approvals });
}
