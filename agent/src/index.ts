import "dotenv/config";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LMStudioClient } from "./llm/lmstudio";
import { createSnykScanTool, createSnykScanner } from "./tools/snyk-scan";
import type { Message, ToolCall } from "./llm/types";
import { createApplyUpgradeTool } from "./tools/apply-upgrade";
import { createRunTestsTool } from "./tools/run-tests";
import { createRevertUpgradeTool } from "./tools/git/revert-upgrade";
import { createGitCommitTool } from "./tools/git/git-commit";
import { gitCreateBranch, gitIsClean, gitCheckoutBranch } from "./tools/git";
import { createCreatePrTool } from "./tools/git/create-pr";
import { createGetVulnDetailsTool } from "./tools/get-vuln-details";
import { createSearchCodeTool } from "./tools/search-code";
import { createReadFileTool } from "./tools/read-file";
import {
  buildRecommendations,
  computeManualReview,
  countVulns,
  mergeManualReview,
  type UpgradeOutcome,
} from "./harness/scan-facts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const targetDir = process.env.TARGET_DIR
  ? path.resolve(process.env.TARGET_DIR)
  : path.resolve(__dirname, "../../snyk-agent-target");

// Phase 2 triage costs several extra calls per unfixable package.
const MAX_ITERATIONS = 80;

/** Tools that change the dependency tree, so the cached scan no longer holds. */
const MUTATING_TOOLS = new Set(["apply_upgrade", "revert_upgrade"]);

/**
 * Record why a package couldn't be fixed, straight from the tool's own result.
 * The model never gets a say in this — it is read off what actually happened.
 */
function recordOutcome(
  call: ToolCall,
  result: string,
  outcomes: Map<string, UpgradeOutcome>,
): void {
  let parsed: Record<string, unknown>;
  try {
    parsed = JSON.parse(result) as Record<string, unknown>;
  } catch {
    return;
  }
  const pkg =
    typeof parsed.package === "string"
      ? parsed.package
      : typeof call.arguments.packageName === "string"
        ? call.arguments.packageName
        : "";
  if (!pkg) return;

  if (call.name === "apply_upgrade" && parsed.ok === false) {
    if (parsed.stage === "guardrail") {
      outcomes.set(pkg, {
        reason:
          `major version bump (${parsed.fromVersion} → ${parsed.recommendedVersion}) ` +
          "requires manual review",
      });
    } else if (parsed.stage === "lookup") {
      outcomes.set(pkg, { reason: "no automated fix available" });
    } else if (typeof parsed.stage === "string") {
      outcomes.set(pkg, { reason: `upgrade failed at ${parsed.stage}` });
    }
  } else if (call.name === "apply_upgrade" && parsed.ok === true) {
    // A later revert may overwrite this; a surviving success means the package
    // is fixed and it won't appear in the final scan anyway.
    outcomes.delete(pkg);
  } else if (call.name === "revert_upgrade" && parsed.ok === true) {
    outcomes.set(pkg, { reason: "upgrade reverted — tests failed" });
  }
}

async function main() {
  const llm = new LMStudioClient();

  const manifests = ["package.json", "package-lock.json"];
  // Guardrail 1: refuse to run on a dirty tree — otherwise a commit could sweep
  // in unrelated uncommitted changes.
  if (!(await gitIsClean(targetDir, manifests))) {
    console.error(
      "Target manifests have uncommitted changes. Reset them first:\n" +
        "  git checkout -- snyk-agent-target/package.json snyk-agent-target/package-lock.json",
    );
    process.exit(1);
  }
  const baseBranch = process.env.BASE_BRANCH ?? "main";

  // Guardrail 2: ALWAYS work on a fresh branch, never commit to the base branch.
  // Creating the branch here (not via a tool) means the model can't skip it.
  await gitCheckoutBranch(targetDir, baseBranch);
  const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 12); // YYYYMMDDHHMM
  const workBranch = `snyk-fix-${stamp}`;
  await gitCreateBranch(targetDir, workBranch);
  console.log(`Working on ${workBranch} (branched from ${baseBranch})`);

  // Guardrail 3: the harness owns the scan. The versions the agent may install
  // and the vulnerabilities the PR must report both come from this data, not
  // from anything the model asserts.
  const scanner = createSnykScanner(targetDir);
  console.log("Running initial Snyk scan…");
  const initialScan = await scanner.scan();
  const recommendations = buildRecommendations(initialScan);
  const vulnsBefore = countVulns(initialScan);
  console.log(
    `Baseline: ${vulnsBefore} vulnerabilities. Snyk-recommended upgrades: ` +
      (Object.entries(recommendations)
        .map(([p, v]) => `${p}@${v}`)
        .join(", ") || "none"),
  );

  /** Why each package could not be fixed, accumulated as tools report back. */
  const outcomes = new Map<string, UpgradeOutcome>();

  const tools = [
    createSnykScanTool(scanner),
    createApplyUpgradeTool(targetDir, recommendations),
    createRunTestsTool(targetDir),
    createRevertUpgradeTool(targetDir),
    createGitCommitTool(targetDir),
    createGetVulnDetailsTool(scanner),
    createSearchCodeTool(targetDir),
    createReadFileTool(targetDir),
    createCreatePrTool(targetDir),
  ];
  const toolMap = new Map(tools.map((t) => [t.definition.name, t]));
  const toolDefs = tools.map((t) => t.definition);

  const messages: Message[] = [
    {
      role: "system",
      content: [
        "You are a dependency security agent for a Node.js project.",
        "",
        "Phase 1 — fix what can be fixed safely:",
        "1. Call snyk_scan to see vulnerabilities and the upgrades that fix them.",
        "2. For EACH upgrade, one package at a time:",
        "   a. Call apply_upgrade with just the package name. You do NOT choose the",
        "      version — the tool installs exactly what Snyk recommends and refuses",
        "      major-version bumps. If it returns ok:false, do NOT retry that package:",
        "      it goes to manual review.",
        "   b. Call run_tests to check the upgrade didn't break the project.",
        "   c. If tests PASS, call git_commit and move to the next package.",
        "   d. If tests FAIL, call revert_upgrade and move on — that package goes to",
        "      manual review.",
        "3. After processing all upgrades, call snyk_scan once more to see what survived.",
        "",
        "Phase 2 — triage every package still vulnerable after Phase 1:",
        "This is judgment work: decide whether the vulnerability is actually exploitable",
        "in THIS codebase. For each still-vulnerable package:",
        "   a. get_vuln_details(packageName) — read the advisory: what is the weakness,",
        "      which API is affected, how does it get triggered?",
        "   b. search_code(pattern) — find where that package or API is used. Search for",
        "      the require, the function name, and for untrusted input (req.body,",
        "      req.query, req.params).",
        "   c. read_file(path) — read the surrounding code at each hit.",
        "   d. Decide: does untrusted input actually reach the vulnerable code? Say so",
        "      either way — 'not reachable' is a valid and useful conclusion.",
        "Every claim you make must cite tool output — a file:line from search_code or",
        "read_file. Never speculate about code you have not read.",
        "",
        "Finally, call create_pull_request with branch, baseBranch, the list of fixed",
        "packages (name, from/to version, vulns fixed), the before/after vulnerability",
        "counts, and a manualReview entry per still-vulnerable package carrying your",
        "triage: 'evidence' (the file:line proof) and 'mitigation' (a concrete fix a",
        "reviewer can act on). The harness recomputes which packages are listed from the",
        "final scan, so omitting one hides nothing — your job is the reasoning.",
      ].join("\n"),
    },
    {
      role: "user",
      content: `Scan the project and fix what you can. You are on branch '${workBranch}', base branch '${baseBranch}'. Apply each fixable upgrade one at a time, committing successes and reverting failures. Then triage everything still vulnerable with get_vuln_details, search_code and read_file, and open a pull request with create_pull_request.`,
    },
  ];

  for (let i = 0; i < MAX_ITERATIONS; i++) {
    const res = await llm.complete(messages, toolDefs);

    if (res.toolCalls.length === 0) {
      console.log("\n=== Agent final answer ===\n" + res.text);
      return;
    }

    // Replay the assistant's tool-call turn before appending results (order matters).
    messages.push({
      role: "assistant",
      content: res.text,
      toolCalls: res.toolCalls,
    });

    for (const call of res.toolCalls) {
      const tool = toolMap.get(call.name);
      let result: string;
      if (!tool) {
        result = JSON.stringify({ error: `Unknown tool: ${call.name}` });
      } else {
        // Guardrail 4: the PR's facts are measured, not asserted. Overwrite the
        // model's manual-review list and counts with what the final scan says,
        // keeping only its per-package reasoning.
        if (call.name === "create_pull_request") {
          await applyHarnessFacts(call, scanner, outcomes, vulnsBefore);
        }
        console.log(`\n→ ${call.name}(${JSON.stringify(call.arguments)})`);
        try {
          result = await tool.execute(call.arguments);
        } catch (err: any) {
          // Feed the error back as the tool result so the model can react, not crash.
          result = JSON.stringify({ error: err?.message ?? String(err) });
        }
        if (MUTATING_TOOLS.has(call.name)) scanner.invalidate();
        recordOutcome(call, result, outcomes);
      }
      console.log(`← ${result}`);
      messages.push({ role: "tool", content: result, toolCallId: call.id });
    }
  }

  console.log(
    `\n⚠️  Hit max iterations (${MAX_ITERATIONS}) without a final answer.`,
  );
}

/**
 * Replace the model's PR claims with harness-computed ones. Runs a final scan if
 * anything has changed since the last one, so "still vulnerable" means what the
 * scanner says right now.
 */
async function applyHarnessFacts(
  call: ToolCall,
  scanner: ReturnType<typeof createSnykScanner>,
  outcomes: Map<string, UpgradeOutcome>,
  vulnsBefore: number,
): Promise<void> {
  const finalScan = await scanner.ensure();
  const computed = computeManualReview(finalScan, outcomes);
  const merged = mergeManualReview(computed, call.arguments.manualReview);

  console.log(
    `\n[harness] manual review computed from final scan: ` +
      (merged.map((m) => `${m.packageName} (${m.severity})`).join(", ") || "none"),
  );

  call.arguments.manualReview = merged;
  call.arguments.vulnsBefore = vulnsBefore;
  call.arguments.vulnsAfter = countVulns(finalScan);
}

main().catch((err) => {
  console.error("Agent run failed:", err);
  process.exit(1);
});
