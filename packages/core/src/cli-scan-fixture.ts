import path from "node:path";
import { RiskRadarService } from "./services";

process.env.RISKRADAR_LOCAL_ROOTS = path.resolve("../../tests/fixtures");

const fixture = path.resolve("../../tests/fixtures/vulnerable-npm-project");
const service = new RiskRadarService();
const project = await service.createProject({ sourceType: "local", localPath: fixture, name: "riskradar-vulnerable-demo" });
const job = await service.scanProject(project.id);
console.log(JSON.stringify({ project, job, radar: service.threatRadar() }, null, 2));
