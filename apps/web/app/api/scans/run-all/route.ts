import { NextResponse } from "next/server";
import { JsonDatabase, RiskRadarService } from "@riskradar/core";

export async function POST() {
  const result = await new RiskRadarService(new JsonDatabase()).scanAll();
  return NextResponse.json(result);
}
