import { runCommand } from "../exec";

/** True if the given paths have no uncommitted changes. */
export async function gitIsClean(cwd: string, paths: string[]): Promise<boolean> {
  const res = await runCommand("git", ["status", "--porcelain", "--", ...paths], cwd);
  if (res.code !== 0) throw new Error(`git status failed: ${res.stderr.trim()}`);
  return res.stdout.trim().length === 0;
}

export async function gitCurrentBranch(cwd: string): Promise<string> {
  const res = await runCommand("git", ["rev-parse", "--abbrev-ref", "HEAD"], cwd);
  if (res.code !== 0) throw new Error(`git rev-parse failed: ${res.stderr.trim()}`);
  return res.stdout.trim();
}

export async function gitCreateBranch(cwd: string, branch: string): Promise<void> {
  const res = await runCommand("git", ["checkout", "-b", branch], cwd);
  if (res.code !== 0) throw new Error(`git checkout -b ${branch} failed: ${res.stderr.trim()}`);
}

/** Discard uncommitted changes to the given paths (restore to last commit). */
export async function gitCheckoutFiles(cwd: string, paths: string[]): Promise<void> {
  const res = await runCommand("git", ["checkout", "--", ...paths], cwd);
  if (res.code !== 0) throw new Error(`git checkout -- failed: ${res.stderr.trim()}`);
}

/** Commit the working-tree version of the given paths. Returns the short SHA. */
export async function gitCommit(cwd: string, paths: string[], message: string): Promise<string> {
  // `commit -- <paths>` commits those paths' working-tree content, ignoring
  // anything else that might be staged — so we never sweep in unrelated changes.
  const commit = await runCommand("git", ["commit", "-m", message, "--", ...paths], cwd);
  if (commit.code !== 0) {
    throw new Error(`git commit failed: ${commit.stderr.trim() || commit.stdout.trim()}`);
  }
  const sha = await runCommand("git", ["rev-parse", "--short", "HEAD"], cwd);
  return sha.stdout.trim();
}

/** Push a branch to origin and set upstream. */
export async function gitPush(cwd: string, branch: string): Promise<void> {
  const res = await runCommand("git", ["push", "-u", "origin", branch], cwd);
  if (res.code !== 0) {
    throw new Error(`git push failed: ${res.stderr.trim() || res.stdout.trim()}`);
  }
}