import { NextRequest, NextResponse } from "next/server";
import { JsonDatabase, RiskRadarError, apiError, getSettings, updateSettings, type StoredSettings } from "@riskradar/core";

export function GET() {
  return NextResponse.json({ ok: true, settings: getSettings(new JsonDatabase()) });
}

// Accepts only known settings keys. No secrets are stored here.
export async function PATCH(request: NextRequest) {
  try {
    const body = (await request.json()) as Record<string, unknown>;
    const patch: StoredSettings = {};
    if (body.watch && typeof body.watch === "object") patch.watch = body.watch as StoredSettings["watch"];
    if (body.failover && typeof body.failover === "object") patch.failover = body.failover as StoredSettings["failover"];
    if (body.scannerToggles && typeof body.scannerToggles === "object") patch.scannerToggles = body.scannerToggles as StoredSettings["scannerToggles"];
    if (body.repoPolicies && typeof body.repoPolicies === "object") patch.repoPolicies = body.repoPolicies as StoredSettings["repoPolicies"];
    if (Object.keys(patch).length === 0) throw new RiskRadarError("no_valid_settings", "No recognized settings keys were provided.");
    const settings = updateSettings(new JsonDatabase(), patch);
    return NextResponse.json({ ok: true, settings });
  } catch (error) {
    return NextResponse.json(apiError(error), { status: error instanceof RiskRadarError ? error.status : 400 });
  }
}
