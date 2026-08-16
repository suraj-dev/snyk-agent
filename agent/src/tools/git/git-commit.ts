import type { Tool } from "../../llm/types";
import { gitCommit } from ".";

const MANIFESTS = ["package.json", "package-lock.json"];

export function createGitCommitTool(targetDir: string): Tool {
  return {
    definition: {
      name: "git_commit",
      description:
        "Commit the current package.json and package-lock.json as one verified " +
        "upgrade. Call ONLY after run_tests (and run_build) have passed for this " +
        "upgrade. Commits just the two manifest files with a standardized message.",
      parameters: {
        type: "object",
        properties: {
          packageName: { type: "string", description: "Upgraded package, e.g. 'axios'" },
          toVersion: { type: "string", description: "Version upgraded to, e.g. '0.32.0'" },
        },
        required: ["packageName", "toVersion"],
      },
    },
    async execute(rawArgs: Record<string, unknown>): Promise<string> {
      const packageName = String(rawArgs.packageName ?? "").trim();
      const toVersion = String(rawArgs.toVersion ?? "").trim();
      if (!packageName || !toVersion) {
        return JSON.stringify({ ok: false, error: "git_commit requires packageName and toVersion" });
      }
      const message = `fix(deps): upgrade ${packageName} to ${toVersion}`;
      try {
        const sha = await gitCommit(targetDir, MANIFESTS, message);
        return JSON.stringify({ ok: true, commit: sha, message });
      } catch (err) {
        return JSON.stringify({ ok: false, error: (err as Error).message });
      }
    },
  };
}