import { NextResponse } from "next/server";
import { JsonDatabase, RiskRadarService, apiError } from "@riskradar/core";

export async function POST(_: Request, { params }: { params: Promise<{ id: string }> }) {
  try {
    const { id } = await params;
    const job = await new RiskRadarService(new JsonDatabase()).rollback(id);
    return NextResponse.json(job);
  } catch (error) {
    return NextResponse.json(apiError(error), { status: 400 });
  }
}
