import { NextResponse } from "next/server";
import { JsonDatabase, watchStatus } from "@riskradar/core";

export function GET() {
  return NextResponse.json({ ok: true, watch: watchStatus(new JsonDatabase()) });
}
