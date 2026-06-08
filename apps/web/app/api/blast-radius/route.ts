import { NextResponse } from "next/server";
import { JsonDatabase, RiskRadarService } from "@riskradar/core";

export function GET() {
  return NextResponse.json({ blastRadius: new RiskRadarService(new JsonDatabase()).blastRadius() });
}
