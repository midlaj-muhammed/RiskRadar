import { NextRequest, NextResponse } from "next/server";
import { JsonDatabase } from "@riskradar/core";

export function GET(request: NextRequest) {
  const status = request.nextUrl.searchParams.get("status");
  const state = new JsonDatabase().read();
  const findings = state.findings
    .filter((finding) => !status || finding.status === status)
    .map((finding) => ({
      ...finding,
      projectName: state.projects.find((project) => project.id === finding.projectId)?.name,
      vulnerability: state.vulnerabilities.find((vulnerability) => vulnerability.id === finding.vulnerabilityId)
    }));
  return NextResponse.json({ findings });
}
