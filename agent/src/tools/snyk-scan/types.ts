export type Severity = "critical" | "high" | "medium" | "low";

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"];

export type SeverityCounts = Record<Severity, number>;

/**
 * A vulnerability as Snyk reports it. Only `id` and `severity` are relied on by
 * the scan summary; the rest are present in the real JSON and are used by
 * get_vuln_details and the harness's manual-review computation. All optional —
 * Snyk omits fields per-vuln (e.g. `functions` is empty for every npm vuln we
 * see) and the tools must degrade rather than assume.
 */
export interface SnykVulnerability {
  id: string;
  severity: Severity;
  title?: string;
  /** The vulnerable module itself, e.g. 'qs' — NOT the top-level dependency. */
  packageName?: string;
  version?: string;
  description?: string;
  cvssScore?: number;
  CVSSv3?: string;
  semver?: { vulnerable?: string[] };
  fixedIn?: string[];
  identifiers?: { CVE?: string[]; CWE?: string[]; GHSA?: string[] };
  /** Dependency path, e.g. ['target@1.0.0', 'express@4.22.0', 'qs@6.14.2']. */
  from?: string[];
  upgradePath?: (string | false)[];
  isUpgradable?: boolean;
  /** Vulnerable function metadata. Empty in practice for npm projects. */
  functions?: SnykFunction[];
  functions_new?: SnykFunction[];
}

export interface SnykFunction {
  functionId?: { className?: string | null; functionName?: string; filePath?: string };
  version?: string[];
}

export interface SnykUpgradeInfo {
  upgradeTo: string;
  vulns: string[];
}

export interface SnykTestResult {
  ok: boolean;
  dependencyCount?: number;
  vulnerabilities?: SnykVulnerability[];
  remediation?: {
    upgrade?: Record<string, SnykUpgradeInfo>;
    /** Vulnerabilities with no upgrade path — the "no automated fix" source. */
    unresolved?: SnykVulnerability[];
  };
}

export interface UpgradeSummary {
  from: string;
  to: string;
  fixes: number;
  severities: SeverityCounts;
}

export interface ScanSummary {
  ok: boolean;
  dependencyCount?: number;
  totalVulnerabilities: number;
  severitySummary: SeverityCounts;
  upgrades: UpgradeSummary[];
}
