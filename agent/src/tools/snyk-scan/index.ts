import { Tool } from "../../llm/types";
import { SnykScanner } from "./scanner";
import { ScanSummary, SeverityCounts, SnykTestResult, UpgradeSummary, Severity } from "./types";

export { createSnykScanner } from "./scanner";
export type { SnykScanner } from "./scanner";

export function createSnykScanTool(scanner: SnykScanner): Tool {
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
      // ensure(), not scan(): the harness scans before the loop starts and
      // invalidates after every dependency change, so this re-runs Snyk exactly
      // when the tree has actually moved.
      const raw = await scanner.ensure();
      return JSON.stringify(distill(raw), null, 2);
    },
  };
}

function zeroCounts(): SeverityCounts {
  return { critical: 0, high: 0, medium: 0, low: 0 };
}

export function distill(raw: SnykTestResult): ScanSummary {
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
