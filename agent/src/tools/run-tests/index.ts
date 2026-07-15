import type { Tool } from "../../llm/types";
import { runCommand } from "../exec";

const MAX_OUTPUT = 4000; // cap chars fed back to the model

function tail(text: string, max: number): string {
  if (text.length <= max) return text;
  return "…(truncated)…\n" + text.slice(text.length - max);
}

export function createRunTestsTool(targetDir: string): Tool {
  return {
    definition: {
      name: "run_tests",
      description:
        "Run the target project's test suite (npm test). Returns whether the tests " +
        "passed and the relevant output. Use after applying an upgrade to confirm " +
        "the change didn't break anything.",
      parameters: { type: "object", properties: {}, required: [] },
    },
    async execute(): Promise<string> {
      const result = await runCommand("npm", ["test"], targetDir);
      const combined = (result.stdout + "\n" + result.stderr).trim();
      return JSON.stringify({
        passed: result.code === 0,
        exitCode: result.code,
        output: tail(combined, MAX_OUTPUT),
      });
    },
  };
}