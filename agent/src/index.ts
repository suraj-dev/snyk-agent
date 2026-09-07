import "dotenv/config";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LMStudioClient } from "./llm/lmstudio";
import { createSnykScanTool } from "./tools/snyk-scan";
import type { Message } from "./llm/types";
import { createApplyUpgradeTool } from "./tools/apply-upgrade";
import { createRunTestsTool } from "./tools/run-tests";
import { createRevertUpgradeTool } from "./tools/git/revert-upgrade";
import { createGitCommitTool } from "./tools/git/git-commit";
import { gitCreateBranch, gitCurrentBranch, gitIsClean } from "./tools/git";
import { createCreatePrTool } from "./tools/git/create-pr";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const targetDir = process.env.TARGET_DIR
  ? path.resolve(process.env.TARGET_DIR)
  : path.resolve(__dirname, "../../snyk-agent-target");

const MAX_ITERATIONS = 40;

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

  // Guardrail 2: ALWAYS work on a fresh branch, never commit to the base branch.
  // Creating the branch here (not via a tool) means the model can't skip it.
  const baseBranch = await gitCurrentBranch(targetDir);
  const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 12); // YYYYMMDDHHMM
  const workBranch = `snyk-fix-${stamp}`;
  await gitCreateBranch(targetDir, workBranch);
  console.log(`Working on ${workBranch} (branched from ${baseBranch})`);
  const tools = [
    createSnykScanTool(targetDir),
    createApplyUpgradeTool(targetDir),
    createRunTestsTool(targetDir),
    createRevertUpgradeTool(targetDir),
    createGitCommitTool(targetDir),
    createGitCommitTool(targetDir),
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
        "Workflow:",
        "1. Call snyk_scan to see vulnerabilities and the upgrades that fix them.",
        "2. When upgrading, only upgrade to the version Snyk recommends (no ranges, no latest).",
        "3. For EACH upgrade, one package at a time:",
        "   a. Call apply_upgrade with the package name and target version.",
        "   b. Call run_tests to check the upgrade didn't break the project.",
        "   c. If tests PASS, keep it and move to the next package.",
        "   d. If tests FAIL, the upgrade is unsafe — report it as needing manual",
        "      review and continue with the remaining packages.",
        "3. After processing all upgrades, call snyk_scan once more to confirm the",
        "   final state, then summarize what was fixed and what needs manual review.",
        "4. Call create_pull_request with branch, baseBranch, the list of fixed packages",
        "   (name, from/to version, vulns fixed), the manual-review list (packages with no",
        "   automated fix), and the before/after total vulnerability counts.",
        "",
        "Apply upgrades individually so a single breaking change can be isolated.",
        "If a vulnerability has NO recommended upgrade in the scan's remediation data,",
        " do NOT attempt to fix it. Record it under a 'manual review required' list with",
        " the package name, severity, and the reason 'no automated fix available'.",
      ].join("\n"),
    },
    {
      role: "user",
      content: `Scan the project and fix what you can. You are on branch '${workBranch}', base branch '${baseBranch}'. Apply each fixable upgrade one at a time, committing successes and reverting failures. When done, open a pull request with create_pull_request, passing the fixed packages, manual-review items, and before/after vulnerability counts.`,
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
        console.log(`\n→ ${call.name}(${JSON.stringify(call.arguments)})`);
        try {
          result = await tool.execute(call.arguments);
        } catch (err: any) {
          // Feed the error back as the tool result so the model can react, not crash.
          result = JSON.stringify({ error: err?.message ?? String(err) });
        }
      }
      console.log(`← ${result}`);
      messages.push({ role: "tool", content: result, toolCallId: call.id });
    }
  }

  console.log(
    `\n⚠️  Hit max iterations (${MAX_ITERATIONS}) without a final answer.`,
  );
}

main().catch((err) => {
  console.error("Agent run failed:", err);
  process.exit(1);
});
