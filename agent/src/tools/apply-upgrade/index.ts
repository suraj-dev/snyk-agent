import type { Tool } from "../../llm/types";
import { runCommand } from "../exec";

interface UpgradeArgs {
  packageName: string;
  toVersion: string;
}

function parseArgs(args: Record<string, unknown>): UpgradeArgs {
  const { packageName, toVersion } = args;
  if (typeof packageName !== "string" || !packageName.trim()) {
    throw new Error("apply_upgrade requires a non-empty 'packageName' string");
  }
  if (typeof toVersion !== "string" || !toVersion.trim()) {
    throw new Error("apply_upgrade requires a non-empty 'toVersion' string");
  }
  return { packageName: packageName.trim(), toVersion: toVersion.trim() };
}

export function createApplyUpgradeTool(targetDir: string): Tool {
  return {
    definition: {
      name: "apply_upgrade",
      description:
        "Upgrade a single dependency to a specific version in the target project. " +
        "Edits package.json and regenerates package-lock.json. Does NOT run tests or " +
        "re-scan — call run_tests and snyk_scan separately afterward to verify.",
      parameters: {
        type: "object",
        properties: {
          packageName: { type: "string", description: "Package name, e.g. 'axios'" },
          toVersion: {
            type: "string",
            description: "Exact target version without a range prefix, e.g. '0.32.0'",
          },
        },
        required: ["packageName", "toVersion"],
      },
    },
    async execute(rawArgs: Record<string, unknown>): Promise<string> {
      const { packageName, toVersion } = parseArgs(rawArgs);
      const spec = `${packageName}@${toVersion}`;

      // 1. Verify the version exists on the registry before editing anything.
      const view = await runCommand("npm", ["view", spec, "version"], targetDir);
      if (view.code !== 0 || !view.stdout.trim()) {
        return JSON.stringify({
          ok: false,
          stage: "verify",
          error: `Version ${spec} was not found on the npm registry`,
          detail: view.stderr.trim() || undefined,
        });
      }

      // 2. Install — updates package.json AND package-lock.json in one step.
      const install = await runCommand(
        "npm",
        ["install", spec, "--save-exact"],
        targetDir
      );
      if (install.code !== 0) {
        return JSON.stringify({
          ok: false,
          stage: "install",
          error: `npm install ${spec} failed (exit ${install.code})`,
          detail: install.stderr.trim() || install.stdout.trim() || undefined,
        });
      }

      return JSON.stringify({
        ok: true,
        package: packageName,
        installedVersion: toVersion,
        note: "Manifest and lockfile updated. Run run_tests and snyk_scan to verify.",
      });
    },
  };
}