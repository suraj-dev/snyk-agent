import type { Tool } from "../../llm/types";
import { runCommand } from "../exec";
import { gitCheckoutFiles } from ".";

const MANIFESTS = ["package.json", "package-lock.json"];

export function createRevertUpgradeTool(targetDir: string): Tool {
  return {
    definition: {
      name: "revert_upgrade",
      description:
        "Undo the most recent UNCOMMITTED dependency upgrade: restore package.json " +
        "and package-lock.json to the last committed state and reinstall dependencies " +
        "to match. Use when an upgrade fails run_tests or run_build. Previously " +
        "committed upgrades are preserved.",
      parameters: {
        type: "object",
        properties: {
          packageName: {
            type: "string",
            description: "The package whose upgrade is being reverted (for the record).",
          },
        },
        required: ["packageName"],
      },
    },
    async execute(rawArgs: Record<string, unknown>): Promise<string> {
      const packageName =
        typeof rawArgs.packageName === "string" ? rawArgs.packageName : "unknown";

      // 1. Restore the manifests to the last commit.
      try {
        await gitCheckoutFiles(targetDir, MANIFESTS);
      } catch (err) {
        return JSON.stringify({
          ok: false, stage: "git", package: packageName, error: (err as Error).message,
        });
      }

      // 2. Reconcile node_modules to the restored lockfile. Git does NOT touch
      //    node_modules (it's gitignored), so the failed upgrade's packages are
      //    still installed on disk. Without this, run_tests would execute against
      //    the reverted-in-manifest-but-still-installed version — a false result.
      const ci = await runCommand("npm", ["ci"], targetDir);
      if (ci.code !== 0) {
        return JSON.stringify({
          ok: false, stage: "npm ci", package: packageName,
          error: `npm ci failed (exit ${ci.code})`,
          detail: (ci.stderr || ci.stdout).trim().slice(-800) || undefined,
        });
      }

      return JSON.stringify({
        ok: true, package: packageName,
        note: "Manifests restored to last commit and dependencies reinstalled to match.",
      });
    },
  };
}