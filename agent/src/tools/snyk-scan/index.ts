import { Tool } from "../../llm/types";
import { runCommand } from "../exec/index";
import { ScanSummary, SeverityCounts, SnykTestResult, UpgradeSummary, Severity } from "./types";

export function createSnykScanTool(targetDir: string): Tool {
  return {
    definition: {
      name: "snyk_scan",
      description:
        "Run a Snyk vulnerability scan on the target project's dependencies. " +
        "Returns a summary of vulnerabilities found and the dependency upgrades " +
        "that would fix them, grouped by top-level package. Takes no arguments.",
      parameters: { type: "object", properties: {}, required: [] },
    },
    async execute(): Promise<string> {
      const raw = await runSnyk(targetDir);
      return JSON.stringify(distill(raw), null, 2);
    },
  };
}

function zeroCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

async function runSnyk(targetDir: string): Promise<SnykTestResult> {
  const result = await runCommand("snyk", ["test", "--json"], targetDir, 20 * 1024 * 1024);
  // Snyk exits with code 1 when it FINDS vulnerabilities — not a real failure.
  if (result.code === 0 || (result.code === 1 && result.stdout.trim())) {
    return parseSnykJson(result.stdout);
  }
  // Exit 2/3, ENOENT (snyk not on PATH), auth failure, etc. → genuine error.
  throw new Error(`snyk test failed (code ${result.code}): ${result.stderr.trim()}`);
}

function parseSnykJson(stdout: string): SnykTestResult {
  return JSON.parse(stdout) as SnykTestResult;
}

function distill(raw: SnykTestResult): ScanSummary {
  // Map each vuln id → severity, which also dedups vulns reachable via multiple paths.
  const sevById = new Map<string, Severity>();
  for (const v of raw.vulnerabilities ?? []) {
    if (v.id) sevById.set(v.id, v.severity);
  }

  const upgradeMap = raw.remediation?.upgrade ?? {};
  const upgrades: UpgradeSummary[] = Object.entries(upgradeMap).map(
    ([from, info]): UpgradeSummary => {
      const severities = zeroCounts();
      for (const id of info.vulns) {
        const sev = sevById.get(id);
        if (sev) severities[sev]++;
      }
      return { from, to: info.upgradeTo, fixes: info.vulns.length, severities };
    }
  );

  const severitySummary = zeroCounts();
  for (const sev of sevById.values()) {
    severitySummary[sev]++;
  }

  return {
    ok: raw.ok,
    dependencyCount: raw.dependencyCount,
    totalVulnerabilities: sevById.size,
    severitySummary,
    upgrades,
  };
}