import { Octokit } from "@octokit/rest";
import { getEnv } from "./env";
import { RiskRadarError } from "./errors";

export function githubClient(): Octokit {
  const token = getEnv("GITHUB_TOKEN");
  if (!token) throw new RiskRadarError("github_token_missing", "Set GITHUB_TOKEN to use GitHub repository and PR operations.", { requiredEnv: "GITHUB_TOKEN" });
  return new Octokit({ auth: token });
}

export async function validateGithubRepo(owner: string, repo: string) {
  try {
    const client = githubClient();
    const response = await client.repos.get({ owner, repo });
    return {
      name: response.data.name,
      fullName: response.data.full_name,
      defaultBranch: response.data.default_branch,
      cloneUrl: response.data.clone_url,
      private: response.data.private,
      archived: response.data.archived
    };
  } catch (error) {
    if (error instanceof RiskRadarError) throw error;
    throw new RiskRadarError("github_repo_not_accessible", "GitHub repo could not be validated with the configured token.", { owner, repo }, 502);
  }
}

/** Closes a pull request (no merge). Used for rollback of a RiskRadar draft PR. */
export async function closePullRequest(owner: string, repo: string, pullNumber: number): Promise<void> {
  const client = githubClient();
  try {
    await client.pulls.update({ owner, repo, pull_number: pullNumber, state: "closed" });
  } catch (error) {
    throw new RiskRadarError("github_pr_close_failed", "GitHub pull request close failed.", { error: error instanceof Error ? error.message : String(error) }, 502);
  }
}

/** Deletes a branch ref. Best-effort: a missing branch is treated as already gone. */
export async function deleteBranchRef(owner: string, repo: string, branch: string): Promise<void> {
  const client = githubClient();
  try {
    await client.git.deleteRef({ owner, repo, ref: `heads/${branch}` });
  } catch (error) {
    const status = (error as { status?: number }).status;
    if (status === 422 || status === 404) return; // already deleted
    throw new RiskRadarError("github_branch_delete_failed", "GitHub branch deletion failed.", { error: error instanceof Error ? error.message : String(error) }, 502);
  }
}

export async function createDraftPullRequest(input: {
  owner: string;
  repo: string;
  title: string;
  head: string;
  base: string;
  body: string;
}) {
  const client = githubClient();
  try {
    const response = await client.pulls.create({ ...input, draft: true });
    return { number: response.data.number, url: response.data.html_url };
  } catch (error) {
    throw new RiskRadarError("github_pr_create_failed", "GitHub pull request creation failed; no PR URL was stored.", { error: error instanceof Error ? error.message : String(error) }, 502);
  }
}

/**
 * Opens a real (non-draft) pull request so it can be merged after the human
 * approves the merge gate. Used by the two-step push→merge Telegram flow.
 */
export async function createPullRequest(input: {
  owner: string;
  repo: string;
  title: string;
  head: string;
  base: string;
  body: string;
  draft?: boolean;
}) {
  const client = githubClient();
  try {
    const response = await client.pulls.create({ ...input, draft: input.draft ?? false });
    return { number: response.data.number, url: response.data.html_url };
  } catch (error) {
    throw new RiskRadarError("github_pr_create_failed", "GitHub pull request creation failed; no PR URL was stored.", { error: error instanceof Error ? error.message : String(error) }, 502);
  }
}

/** Merges a pull request (squash by default). Used when the human taps "Merge". */
export async function mergePullRequest(owner: string, repo: string, pullNumber: number, options: { method?: "merge" | "squash" | "rebase"; commitTitle?: string } = {}): Promise<{ merged: boolean; sha?: string }> {
  const client = githubClient();
  try {
    const response = await client.pulls.merge({
      owner,
      repo,
      pull_number: pullNumber,
      merge_method: options.method ?? "squash",
      ...(options.commitTitle ? { commit_title: options.commitTitle } : {})
    });
    return { merged: Boolean(response.data.merged), sha: response.data.sha };
  } catch (error) {
    throw new RiskRadarError("github_pr_merge_failed", "GitHub pull request merge failed.", { error: error instanceof Error ? error.message : String(error) }, 502);
  }
}
