import { NextResponse } from "next/server";
import { JsonDatabase, RiskRadarService } from "@riskradar/core";

export function GET() {
  return NextResponse.json(new RiskRadarService(new JsonDatabase()).threatRadar());
}
