import type { Tool } from "../../llm/types";
import type { SnykScanner } from "../snyk-scan/scanner";
import type { SnykFunction, SnykVulnerability } from "../snyk-scan/types";
import { splitSpec } from "../../harness/scan-facts";

const MAX_VULNS = 10;
const MAX_DESCRIPTION = 600;

function excerpt(text: string | undefined, max: number): string | undefined {
  if (!text) return undefined;
  const flat = text.replace(/\s+/g, " ").trim();
  return flat.length <= max ? flat : flat.slice(0, max) + "…";
}

/** Function names Snyk flags as vulnerable. Empty for npm advisories in practice. */
function functionNames(v: SnykVulnerability): string[] {
  const all: SnykFunction[] = [...(v.functions ?? []), ...(v.functions_new ?? [])];
  const names = all
    .map((f) => {
      const id = f.functionId;
      if (!id?.functionName) return undefined;
      return id.className ? `${id.className}.${id.functionName}` : id.functionName;
    })
    .filter((n): n is string => Boolean(n));
  return [...new Set(names)];
}

export function createGetVulnDetailsTool(scanner: SnykScanner): Tool {
  return {
    definition: {
      name: "get_vuln_details",
      description:
        "Get the full advisory detail for a package's vulnerabilities: title, severity, " +
        "CVSS, the vulnerable version range, CVE/CWE identifiers, the dependency path, " +
        "and a description excerpt. Matches both direct vulnerabilities in the package " +
        "and vulnerabilities reached THROUGH it (asking about 'express' also returns the " +
        "qs and body-parser vulnerabilities it pulls in). Use this before judging whether " +
        "a vulnerability is exploitable in this codebase.",
      parameters: {
        type: "object",
        properties: {
          packageName: {
            type: "string",
            description: "Package name, e.g. 'body-parser' or 'express'",
          },
        },
        required: ["packageName"],
      },
    },
    async execute(rawArgs: Record<string, unknown>): Promise<string> {
      const packageName =
        typeof rawArgs.packageName === "string" ? rawArgs.packageName.trim() : "";
      if (!packageName) {
        return JSON.stringify({
          ok: false,
          stage: "args",
          error: "get_vuln_details requires a non-empty 'packageName' string",
        });
      }

      let vulns: SnykVulnerability[];
      try {
        const scan = await scanner.ensure();
        vulns = scan.vulnerabilities ?? [];
      } catch (err) {
        return JSON.stringify({ ok: false, stage: "scan", error: (err as Error).message });
      }

      const seen = new Set<string>();
      const matches = vulns.filter((v) => {
        const topLevel = v.from?.[1] ? splitSpec(v.from[1]).name : undefined;
        if (v.packageName !== packageName && topLevel !== packageName) return false;
        if (!v.id || seen.has(v.id)) return false;
        seen.add(v.id);
        return true;
      });

      if (matches.length === 0) {
        return JSON.stringify({
          ok: true,
          package: packageName,
          vulnerabilities: [],
          note: `No vulnerabilities recorded for '${packageName}' in the current scan.`,
        });
      }

      const details = matches.slice(0, MAX_VULNS).map((v) => {
        const functions = functionNames(v);
        return {
          id: v.id,
          title: v.title,
          severity: v.severity,
          cvssScore: v.cvssScore,
          cvssVector: v.CVSSv3,
          module: v.packageName,
          installedVersion: v.version,
          vulnerableRange: v.semver?.vulnerable,
          fixedIn: v.fixedIn,
          cve: v.identifiers?.CVE,
          cwe: v.identifiers?.CWE,
          path: v.from,
          vulnerableFunctions: functions.length ? functions : undefined,
          description: excerpt(v.description, MAX_DESCRIPTION),
        };
      });

      const anyFunctions = details.some((d) => d.vulnerableFunctions);
      return JSON.stringify(
        {
          ok: true,
          package: packageName,
          total: matches.length,
          returned: details.length,
          functionsAvailable: anyFunctions,
          note: anyFunctions
            ? undefined
            : "Snyk lists no vulnerable function names for these advisories. Use search_code " +
              "to find where this package (or the API described above) is used in the target, " +
              "then read_file to judge reachability.",
          vulnerabilities: details,
        },
        null,
        2
      );
    },
  };
}
