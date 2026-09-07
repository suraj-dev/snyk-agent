import type { Severity, SnykTestResult, SnykVulnerability } from "../tools/snyk-scan/types";

/** Split 'express@4.22.0' / '@scope/pkg@1.2.3' into name and version. */
export function splitSpec(spec: string): { name: string; version: string } {
  const at = spec.lastIndexOf("@");
  if (at <= 0) return { name: spec, version: "" };
  return { name: spec.slice(0, at), version: spec.slice(at + 1) };
}

/**
 * packageName → exact version, from Snyk's remediation.upgrade. Keys there look
 * like 'express@4.22.0' and upgradeTo like 'express@5.1.0'; the agent only ever
 * installs a version that came out of this map.
 */
export function buildRecommendations(scan: SnykTestResult): Record<string, string> {
  const out: Record<string, string> = {};
  for (const info of Object.values(scan.remediation?.upgrade ?? {})) {
    const { name, version } = splitSpec(info.upgradeTo);
    if (name && version) out[name] = version;
  }
  return out;
}

/** Unique vulnerability count — same dedup rule the scan summary uses. */
export function countVulns(scan: SnykTestResult): number {
  const ids = new Set<string>();
  for (const v of scan.vulnerabilities ?? []) {
    if (v.id) ids.add(v.id);
  }
  return ids.size;
}

const SEVERITY_RANK: Record<Severity, number> = { critical: 3, high: 2, medium: 1, low: 0 };

/** The top-level dependency a vuln is reached through, e.g. qs → express. */
export function topLevelOf(v: SnykVulnerability): string | undefined {
  const entry = v.from?.[1];
  return entry ? splitSpec(entry).name : undefined;
}

/** Why a package couldn't be fixed, recorded by the harness as tools report back. */
export interface UpgradeOutcome {
  reason: string;
}

export interface ManualReviewItem {
  packageName: string;
  /** Top-level dependency this vulnerable module arrives through, if indirect. */
  via?: string;
  severity: Severity;
  vulnCount: number;
  reason: string;
  /** Filled in by the model's Phase-2 triage, never required. */
  evidence?: string;
  mitigation?: string;
}

/**
 * Every vulnerability still present in the FINAL scan becomes a manual-review
 * item. Derived from scan data plus the harness's own record of what happened,
 * so the model cannot make an item disappear by omitting it.
 */
export function computeManualReview(
  finalScan: SnykTestResult,
  outcomes: Map<string, UpgradeOutcome>
): ManualReviewItem[] {
  const unresolvedIds = new Set(
    (finalScan.remediation?.unresolved ?? []).map((v) => v.id).filter(Boolean)
  );

  // Pass 1: group the surviving vulnerabilities by the module they live in.
  const groups = new Map<string, { via?: string; vulns: SnykVulnerability[] }>();
  const seenIds = new Set<string>();

  for (const v of finalScan.vulnerabilities ?? []) {
    if (!v.id || seenIds.has(v.id)) continue;
    seenIds.add(v.id);

    const pkg = v.packageName ?? splitSpec(v.from?.[v.from.length - 1] ?? "").name;
    if (!pkg) continue;
    const via = topLevelOf(v);

    const group = groups.get(pkg);
    if (group) {
      group.vulns.push(v);
    } else {
      groups.set(pkg, { via: via && via !== pkg ? via : undefined, vulns: [v] });
    }
  }

  // Pass 2: one item per module, with the most accurate reason available.
  const items: ManualReviewItem[] = [];
  for (const [packageName, { via, vulns }] of groups) {
    const severity = vulns.reduce<Severity>(
      (worst, v) => (SEVERITY_RANK[v.severity] > SEVERITY_RANK[worst] ? v.severity : worst),
      vulns[0].severity
    );

    // Precedence: what happened to this module directly, then the scan's own
    // "nothing fixes this" signal, then whatever blocked the top-level package
    // it arrives through (express's refused major is why qs is still here).
    // Order matters: body-parser is unresolved outright, so it must not inherit
    // express's major-bump reason and imply a fix exists.
    const allUnresolved = vulns.every((v) => unresolvedIds.has(v.id));
    const reason =
      outcomes.get(packageName)?.reason ??
      (allUnresolved ? "no automated fix available" : undefined) ??
      (via ? outcomes.get(via)?.reason : undefined) ??
      (vulns.some((v) => unresolvedIds.has(v.id))
        ? "no automated fix available for some vulnerabilities"
        : "still vulnerable after fix attempts");

    items.push({ packageName, via, severity, vulnCount: vulns.length, reason });
  }

  return items.sort(
    (a, b) =>
      SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] ||
      a.packageName.localeCompare(b.packageName)
  );
}

/**
 * The computed list decides WHICH packages appear; the model may only enrich
 * matching entries with triage detail. Entries the model invented are dropped.
 */
export function mergeManualReview(
  computed: ManualReviewItem[],
  fromModel: unknown
): ManualReviewItem[] {
  const supplied = new Map<string, Record<string, unknown>>();
  if (Array.isArray(fromModel)) {
    for (const raw of fromModel) {
      if (raw && typeof raw === "object") {
        const item = raw as Record<string, unknown>;
        const name = typeof item.packageName === "string" ? item.packageName.trim() : "";
        if (name) supplied.set(name, item);
      }
    }
  }

  return computed.map((item) => {
    const extra = supplied.get(item.packageName);
    if (!extra) return item;
    const str = (k: string): string | undefined => {
      const val = extra[k];
      return typeof val === "string" && val.trim() ? val.trim() : undefined;
    };
    const modelReason = str("reason");
    return {
      ...item,
      // The model's reason is only allowed to ADD detail to the computed one.
      reason: modelReason && modelReason !== item.reason
        ? `${item.reason} — ${modelReason}`
        : item.reason,
      evidence: str("evidence"),
      mitigation: str("mitigation"),
    };
  });
}
