import { NextRequest, NextResponse } from "next/server";
import { JsonDatabase, RiskRadarService, apiError } from "@riskradar/core";

export async function GET() {
  return NextResponse.json({ projects: new RiskRadarService(new JsonDatabase()).listProjects() });
}

export async function POST(request: NextRequest) {
  const service = new RiskRadarService(new JsonDatabase());
  try {
    const contentType = request.headers.get("content-type") ?? "";
    let input: Record<string, string | undefined>;
    if (contentType.includes("application/json")) {
      input = await request.json();
    } else {
      const form = await request.formData();
      const github = String(form.get("github") ?? "");
      const [githubOwner, githubRepo] = github.split("/");
      input = {
        sourceType: String(form.get("sourceType") ?? "local"),
        name: String(form.get("name") ?? "") || undefined,
        localPath: String(form.get("localPath") ?? "") || undefined,
        githubOwner,
        githubRepo
      };
    }
    const project = await service.createProject({
      sourceType: input.sourceType as never,
      name: input.name,
      localPath: input.localPath,
      githubOwner: input.githubOwner,
      githubRepo: input.githubRepo,
      deploymentUrl: input.deploymentUrl,
      productionExposed: input.productionExposed === "true"
    });
    if (!contentType.includes("application/json")) return NextResponse.redirect(new URL("/projects", request.url), 303);
    return NextResponse.json(project);
  } catch (error) {
    return NextResponse.json(apiError(error), { status: error instanceof Error && "status" in error ? Number(error.status) : 400 });
  }
}
