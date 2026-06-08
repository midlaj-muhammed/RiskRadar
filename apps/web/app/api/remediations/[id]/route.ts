import { NextResponse } from "next/server";
import { JsonDatabase } from "@riskradar/core";

export async function GET(_: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const state = new JsonDatabase().read();
  const job = state.remediationJobs.find((item) => item.id === id);
  if (!job) return NextResponse.json({ error: { code: "remediation_not_found", message: "Remediation job was not found.", details: { id } } }, { status: 404 });
  return NextResponse.json({
    ...job,
    events: state.jobEvents.filter((event) => event.jobId === id),
    validationRuns: state.validationRuns.filter((run) => run.remediationJobId === id),
    pullRequest: state.pullRequests.find((pr) => pr.remediationJobId === id),
    approval: state.approvals.find((approval) => approval.remediationJobId === id)
  });
}
