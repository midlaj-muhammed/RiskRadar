export type SourceType = "github" | "local" | "vercel-linked" | "server";
export type PackageManager = "npm" | "pnpm" | "yarn" | "pip" | "unknown";
export type RiskLevel = "low" | "medium" | "high" | "critical";
export type JobStatus =
  | "queued"
  | "running"
  | "completed"
  | "failed_external_service"
  | "failed_invalid_project"
  | "failed_internal_error"
  | "codex_not_executed"
  | "validation_failed"
  | "pr_ready"
  | "approval_sent"
  | "push_pending"
  | "pr_open"
  | "merged"
  | "discarded"
  | "approved"
  | "rejected"
  | "failed";

export interface Project {
  id: string;
  name: string;
  sourceType: SourceType;
  githubOwner?: string;
  githubRepo?: string;
  githubDefaultBranch?: string;
  repoUrl?: string;
  localPath?: string;
  isPathAllowlisted: boolean;
  packageManager: PackageManager;
  deploymentProvider: "vercel" | "unknown" | "none" | "manual";
  deploymentUrl?: string;
  productionExposed: boolean;
  archived?: boolean;
  private?: boolean;
  stack?: string[];
  lastScanAt?: string;
  lastScanStatus?: string;
  createdAt: string;
  updatedAt: string;
}

export interface ScanJob {
  id: string;
  projectId: string;
  status: JobStatus;
  scanner?: "osv-scanner" | "osv-api" | "agent-config";
  startedAt?: string;
  finishedAt?: string;
  errorCode?: string;
  errorMessage?: string;
  rawOutputPath?: string;
  createdAt: string;
}

export interface Vulnerability {
  id: string;
  source: "osv" | "nvd" | "ghsa" | "openssf";
  osvId?: string;
  cveIds: string[];
  ghsaIds: string[];
  summary: string;
  details?: string;
  severity: string;
  cvssScore?: number;
  publishedAt?: string;
  modifiedAt?: string;
  references: string[];
  enrichment?: {
    nvd?: "found" | "not_found" | "error";
    ghsa?: "found" | "not_found" | "error";
  };
  enrichmentErrors?: Record<string, string>;
}

export interface Finding {
  id: string;
  projectId: string;
  scanJobId?: string;
  vulnerabilityId: string;
  packageName: string;
  ecosystem: string;
  currentVersion: string;
  fixedVersion?: string;
  affectedRanges?: string[];
  dependencyType: "direct" | "transitive" | "unknown";
  manifestPath?: string;
  lockfilePath?: string;
  riskScore: number;
  riskLevel: RiskLevel;
  riskFactors: string[];
  missingRiskData: string[];
  fixStrategy: "safe_patch" | "minor_upgrade" | "major_upgrade" | "mitigation" | "manual_review" | "no_fix";
  status: "open" | "fix_available" | "fix_running" | "pr_ready" | "awaiting_approval" | "approved" | "rejected" | "ignored" | "resolved";
  scanConfidence: "lockfile" | "direct_manifest_only" | "unknown";
  // Reachability / VEX-lite triage: is the vulnerable package actually imported
  // in first-party source? Used to de-prioritize likely-unreachable findings.
  reachability?: "imported" | "not_imported" | "indirect" | "unknown";
  reachabilityEvidence?: string;
  createdAt: string;
  updatedAt: string;
}

export interface RiskSignal {
  id: string;
  findingId: string;
  epssProbability?: number;
  epssPercentile?: number;
  isInKev?: boolean;
  kevDueDate?: string;
  kevKnownRansomwareUse?: string;
  isProductionExposed?: boolean;
  isDirectDependency?: boolean;
  hasFix?: boolean;
  hasInstallScripts?: boolean;
  isNewPackageVersion?: boolean;
  notes: string[];
}

export interface RemediationJob {
  id: string;
  findingId: string;
  projectId: string;
  status: JobStatus;
  agent: "codex" | "manual" | "openai" | "openrouter" | "openai-compatible" | "anthropic" | "grok" | "ollama" | "deterministic-npm";
  workspacePath?: string;
  branchName?: string;
  baseBranch?: string;
  startedAt?: string;
  finishedAt?: string;
  errorCode?: string;
  errorMessage?: string;
  fixConfidence?: number;
  summary?: string;
  changedFiles: string[];
  patchPath?: string;
  patchAppliedAt?: string;
  rollbackStatus?: "not_available" | "available" | "requested" | "completed" | "failed";
  /** Rendered PR body, stashed at fix time so the push gate can open the PR later. */
  prBody?: string;
  createdAt: string;
}

export interface JobEvent {
  id: string;
  jobType: "scan" | "remediation" | "validation" | "approval" | "rollback";
  jobId: string;
  type: string;
  level: "debug" | "info" | "warn" | "error";
  message: string;
  data?: Record<string, unknown>;
  createdAt: string;
}

export interface ValidationRun {
  id: string;
  remediationJobId: string;
  command: string;
  status: "passed" | "failed" | "skipped_no_script" | "timeout";
  exitCode?: number;
  durationMs: number;
  logPath?: string;
  createdAt: string;
}

export interface PullRequestRecord {
  id: string;
  remediationJobId: string;
  provider: "github";
  owner: string;
  repo: string;
  number?: number;
  url?: string;
  branchName: string;
  baseBranch: string;
  draft: boolean;
  status: "created" | "failed" | "closed" | "merged";
  errorMessage?: string;
  createdAt: string;
}

export interface ApprovalRequest {
  id: string;
  remediationJobId: string;
  channel: "telegram" | "openclaw";
  chatIdHash?: string;
  messageId?: string;
  status: "pending" | "approved" | "rejected" | "expired" | "unauthorized";
  expiresAt: string;
  createdAt: string;
  updatedAt: string;
}

export interface AuditReceipt {
  id: string;
  projectId?: string;
  actorType: "user" | "system" | "agent" | "mcp" | "plugin";
  actorId?: string;
  agent?: string;
  channel?: string;
  action: string;
  targetType: string;
  targetId: string;
  inputSummary?: unknown;
  outputSummary?: unknown;
  changedFiles: string[];
  commandLogsRef?: string;
  prLink?: string;
  approvalChannel?: string;
  before?: unknown;
  after?: unknown;
  redacted: boolean;
  previousReceiptHash?: string;
  receiptHash: string;
  createdAt: string;
}

export interface AgentConfigFinding {
  id: string;
  projectId?: string;
  filePath: string;
  line?: number;
  field?: string;
  reason: string;
  severity: "low" | "medium" | "high" | "critical";
  recommendation: string;
  redactedSnippet?: string;
  createdAt: string;
}

export interface IntegrationHealth {
  name: string;
  status: "configured" | "not_configured" | "available" | "unavailable" | "error";
  message: string;
  requiredEnv?: string[];
}

export interface WatchRun {
  id: string;
  startedAt: string;
  finishedAt?: string;
  scannedProjects: number;
  newFindings: number;
  alertsSent: number;
  dedupedFindings: number;
  status: "running" | "completed" | "failed" | "skipped_quiet_hours";
  errorMessage?: string;
}

export interface RiskRadarState {
  projects: Project[];
  scanJobs: ScanJob[];
  vulnerabilities: Vulnerability[];
  findings: Finding[];
  riskSignals: RiskSignal[];
  remediationJobs: RemediationJob[];
  jobEvents: JobEvent[];
  validationRuns: ValidationRun[];
  pullRequests: PullRequestRecord[];
  approvals: ApprovalRequest[];
  auditReceipts: AuditReceipt[];
  agentFindings: AgentConfigFinding[];
  // Optional/late-added collections (merged from emptyState for older DBs).
  settings?: StoredSettings;
  watchRuns?: WatchRun[];
  watchAlerts?: WatchAlert[];
  providerConsents?: ProviderConsent[];
  scannerFindings?: StoredScannerFinding[];
}

/** Persisted partial settings overrides (env provides the defaults). */
export interface StoredSettings {
  watch?: Partial<WatchSettings>;
  failover?: Partial<FailoverSettings>;
  repoPolicies?: Record<string, RepoFailoverPolicy>;
  scannerToggles?: Record<string, boolean>;
}

export interface WatchSettings {
  enabled: boolean;
  intervalMinutes: number;
  quietHours?: string;
  telegramAlerts: boolean;
}

export type FailoverMode = "ask" | "automatic" | "disabled";

export interface FailoverSettings {
  mode: FailoverMode;
  chain: string[];
  allowCloudFailover: boolean;
  allowLocalFailover: boolean;
  requireConsentForLowerTrust: boolean;
  fast: boolean;
  maxAttempts: number;
  readinessTimeoutMs: number;
  attemptTimeoutMs: number;
  readinessCacheTtlMs: number;
}

export interface RepoFailoverPolicy {
  alwaysAllowLocal?: boolean;
}

/** Fully resolved settings (env defaults overlaid with persisted overrides). */
export interface RiskRadarSettings {
  watch: WatchSettings;
  failover: FailoverSettings;
  repoPolicies: Record<string, RepoFailoverPolicy>;
  scannerToggles: Record<string, boolean>;
}

/** Persisted scanner finding (structurally compatible with ScannerFinding + projectId). */
export interface StoredScannerFinding {
  id: string;
  projectId: string;
  scanner: string;
  category: string;
  severity: string;
  title: string;
  description: string;
  evidencePath?: string;
  evidenceLine?: number;
  redactedEvidence?: string;
  packageName?: string;
  source: string;
  confidence: string;
  remediation?: string;
  createdAt: string;
}

export interface ProviderConsent {
  id: string;
  findingId: string;
  projectId: string;
  failedProvider: string;
  candidateProvider: string;
  candidateTrust: "codex" | "cloud" | "local" | "deterministic";
  status: "pending" | "approved" | "rejected" | "resolved" | "expired";
  readinessSummary: Array<{ provider: string; status: string; latencyMs?: number; failureReason?: string }>;
  resultRemediationJobId?: string;
  createdAt: string;
  updatedAt: string;
}

export interface WatchAlert {
  id: string;
  projectId: string;
  dedupeKey: string;
  findingId?: string;
  packageName: string;
  advisoryId: string;
  severity: string;
  channel: "telegram" | "dashboard";
  sentAt: string;
}
