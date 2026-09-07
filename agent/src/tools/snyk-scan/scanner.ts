import { runCommand } from "../exec";
import { SnykTestResult } from "./types";

/**
 * Owns the Snyk process and the last raw result, so the harness, the snyk_scan
 * tool and get_vuln_details all read the same scan instead of each paying for
 * their own ~20s run.
 */
export interface SnykScanner {
  /** Always runs Snyk, replacing the cached result. */
  scan(): Promise<SnykTestResult>;
  /** The cached result, re-scanning only if there is none or it was invalidated. */
  ensure(): Promise<SnykTestResult>;
  /** Mark the cache stale — call after anything that changes the dependencies. */
  invalidate(): void;
}

export function createSnykScanner(targetDir: string): SnykScanner {
  let cached: SnykTestResult | null = null;

  return {
    async scan(): Promise<SnykTestResult> {
      cached = await runSnyk(targetDir);
      return cached;
    },
    async ensure(): Promise<SnykTestResult> {
      if (cached) return cached;
      cached = await runSnyk(targetDir);
      return cached;
    },
    invalidate(): void {
      cached = null;
    },
  };
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
