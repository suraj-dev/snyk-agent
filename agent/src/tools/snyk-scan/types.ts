export type Severity = "critical" | "high" | "medium" | "low";

export const SEVERITIES: readonly Severity[] = ["critical", "high", "medium", "low"];

export type SeverityCounts = Record<Severity, number>;

export interface SnykVulnerability {
  id: string;
  severity: Severity;
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