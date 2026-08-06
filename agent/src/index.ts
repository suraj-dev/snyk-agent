import "dotenv/config";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { LMStudioClient } from "./llm/lmstudio";
import { createSnykScanTool } from "./tools/snyk-scan";
import type { Message } from "./llm/types";
import { createApplyUpgradeTool } from "./tools/apply-upgrade";
import { createRunTestsTool } from "./tools/run-tests";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const targetDir = process.env.TARGET_DIR
  ? path.resolve(process.env.TARGET_DIR)
  : path.resolve(__dirname, "../../snyk-agent-target");

const MAX_ITERATIONS = 25;

async function main() {
  const llm = new LMStudioClient();

  const tools = [
    createSnykScanTool(targetDir),
    createApplyUpgradeTool(targetDir),
    createRunTestsTool(targetDir),
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
        "2. For EACH upgrade, one package at a time:",
        "   a. Call apply_upgrade with the package name and target version.",
        "   b. Call run_tests to check the upgrade didn't break the project.",
        "   c. If tests PASS, keep it and move to the next package.",
        "   d. If tests FAIL, the upgrade is unsafe — report it as needing manual",
        "      review and continue with the remaining packages.",
        "3. After processing all upgrades, call snyk_scan once more to confirm the",
        "   final state, then summarize what was fixed and what needs manual review.",
        "",
        "Apply upgrades individually so a single breaking change can be isolated.",
      ].join("\n"),
    },
    {
      role: "user",
      content: "Scan the project and tell me what needs fixing.",
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
