import type { Tool } from "../../llm/types";
import { runCommand } from "../exec";

interface UpgradeArgs {
  packageName: string;
}

function parseArgs(args: Record<string, unknown>): UpgradeArgs {
  const { packageName } = args;
  if (typeof packageName !== "string" || !packageName.trim()) {
    throw new Error("apply_upgrade requires a non-empty 'packageName' string");
  }
  return { packageName: packageName.trim() };
}

/** Leading integer of a semver-ish string, or null if it isn't one. */
function major(version: string): number | null {
  const n = Number.parseInt(version.trim().replace(/^[^\d]*/, "").split(".")[0] ?? "", 10);
  return Number.isNaN(n) ? null : n;
}

/**
 * True when `to` is a higher major than `from`. Unknown/unparseable versions are
 * NOT treated as a major bump — the caller decides what to do without a reading.
 */
export function isMajorBump(from: string, to: string): boolean {
  const a = major(from);
  const b = major(to);
  if (a === null || b === null) return false;
  return b > a;
}

/**
 * Read the installed version of a package from the target's node_modules.
 * `npm ls` exits 1 for perfectly normal trees (extraneous/peer complaints) while
 * still emitting valid JSON, so parse stdout whenever there is any.
 */
async function installedVersion(targetDir: string, pkg: string): Promise<string | null> {
  const ls = await runCommand("npm", ["ls", pkg, "--depth=0", "--json"], targetDir);
  if (!ls.stdout.trim()) return null;
  try {
    const tree = JSON.parse(ls.stdout) as {
      dependencies?: Record<string, { version?: string }>;
    };
    return tree.dependencies?.[pkg]?.version ?? null;
  } catch {
    return null;
  }
}

/** Fallback when node_modules can't answer: the range declared in package.json. */
async function declaredVersion(targetDir: string, pkg: string): Promise<string | null> {
  const view = await runCommand(
    "node",
    ["-e", `const p=require('./package.json');const d={...p.dependencies,...p.devDependencies};process.stdout.write(d[process.argv[1]]??'')`, pkg],
    targetDir
  );
  const raw = view.stdout.trim();
  return raw || null;
}

export function createApplyUpgradeTool(
  targetDir: string,
  recommendations: Record<string, string>
): Tool {
  return {
    definition: {
      name: "apply_upgrade",
      description:
        "Upgrade a single dependency to the version Snyk recommends for it. " +
        "You do NOT choose the version — the tool looks it up from the scan's " +
        "remediation data and refuses anything else, including major-version bumps. " +
        "Edits package.json and regenerates package-lock.json. Does NOT run tests or " +
        "re-scan — call run_tests and snyk_scan separately afterward to verify.",
      parameters: {
        type: "object",
        properties: {
          packageName: { type: "string", description: "Package name, e.g. 'axios'" },
        },
        required: ["packageName"],
      },
    },
    async execute(rawArgs: Record<string, unknown>): Promise<string> {
      const { packageName } = parseArgs(rawArgs);

      // 1. The version comes from Snyk's remediation, never from the model.
      const toVersion = recommendations[packageName];
      if (!toVersion) {
        return JSON.stringify({
          ok: false,
          stage: "lookup",
          package: packageName,
          error: `Snyk has no recommended upgrade for '${packageName}'`,
          available: Object.keys(recommendations),
          instruction:
            "There is no automated fix for this package. Do not retry. Report it " +
            "for manual review with the reason 'no automated fix available'.",
        });
      }

      // 2. Where we're coming from. Two sources, because they can disagree: a
      //    previous run can leave node_modules ahead of the manifest, and
      //    trusting only the installed version would let that stale state wave a
      //    major bump straight through. The manifest is what actually gets
      //    committed, so it's reported — but the guardrail below considers both.
      const declared = await declaredVersion(targetDir, packageName);
      const installed = await installedVersion(targetDir, packageName);
      const fromVersion = declared ?? installed;

      // 3. Guardrail: never ship a major bump as a routine security fix, even
      //    when Snyk itself recommends one (it does for express 4 → 5). A major
      //    jump from EITHER reading is enough to refuse.
      const isMajor =
        (!!declared && isMajorBump(declared, toVersion)) ||
        (!!installed && isMajorBump(installed, toVersion));
      if (isMajor) {
        return JSON.stringify({
          ok: false,
          stage: "guardrail",
          major: true,
          package: packageName,
          fromVersion,
          declaredVersion: declared ?? undefined,
          installedVersion: installed ?? undefined,
          recommendedVersion: toVersion,
          error:
            `Snyk recommends ${packageName}@${toVersion}, a major-version bump from ` +
            `${fromVersion}. Major bumps carry breaking changes and are not applied automatically.`,
          instruction:
            "Do not retry this package. Report it for manual review with the reason " +
            "'major version bump requires manual review'.",
        });
      }

      const spec = `${packageName}@${toVersion}`;

      // 4. Verify the version exists on the registry before editing anything.
      const view = await runCommand("npm", ["view", spec, "version"], targetDir);
      if (view.code !== 0 || !view.stdout.trim()) {
        return JSON.stringify({
          ok: false,
          stage: "verify",
          package: packageName,
          error: `Version ${spec} was not found on the npm registry`,
          detail: view.stderr.trim() || undefined,
        });
      }

      // 5. Install — updates package.json AND package-lock.json in one step.
      const install = await runCommand(
        "npm",
        ["install", spec, "--save-exact"],
        targetDir
      );
      if (install.code !== 0) {
        return JSON.stringify({
          ok: false,
          stage: "install",
          package: packageName,
          error: `npm install ${spec} failed (exit ${install.code})`,
          detail: install.stderr.trim() || install.stdout.trim() || undefined,
        });
      }

      return JSON.stringify({
        ok: true,
        package: packageName,
        fromVersion: fromVersion ?? undefined,
        installedVersion: toVersion,
        note: "Manifest and lockfile updated. Run run_tests and snyk_scan to verify.",
      });
    },
  };
}
