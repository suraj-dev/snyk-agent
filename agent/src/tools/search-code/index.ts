import type { Tool } from "../../llm/types";
import { runCommand } from "../exec";

const MAX_MATCHES = 50;
const MAX_LINE = 200;

interface Match {
  file: string;
  line: number;
  content: string;
}

function parseGrepLine(raw: string): Match | null {
  // Format: ./path/to/file.js:42:the matching source line
  const first = raw.indexOf(":");
  if (first === -1) return null;
  const second = raw.indexOf(":", first + 1);
  if (second === -1) return null;
  const line = Number.parseInt(raw.slice(first + 1, second), 10);
  if (Number.isNaN(line)) return null;
  const content = raw.slice(second + 1).trim();
  return {
    file: raw.slice(0, first).replace(/^\.\//, ""),
    line,
    content: content.length > MAX_LINE ? content.slice(0, MAX_LINE) + "…" : content,
  };
}

export function createSearchCodeTool(targetDir: string): Tool {
  return {
    definition: {
      name: "search_code",
      description:
        "Search the target project's JavaScript source for a pattern (node_modules " +
        "excluded). Returns file, line number and the matching line. Use it to find " +
        "where a vulnerable package or API is actually called, e.g. \"require('lodash')\", " +
        "'_.merge', 'req.body'. No matches is a normal result, not an error.",
      parameters: {
        type: "object",
        properties: {
          pattern: {
            type: "string",
            description: "Text or basic regular expression to search for.",
          },
        },
        required: ["pattern"],
      },
    },
    async execute(rawArgs: Record<string, unknown>): Promise<string> {
      const pattern = typeof rawArgs.pattern === "string" ? rawArgs.pattern : "";
      if (!pattern.trim()) {
        return JSON.stringify({
          ok: false,
          stage: "args",
          error: "search_code requires a non-empty 'pattern' string",
        });
      }

      // execFile, not a shell — the pattern is passed as an argv entry, and `--`
      // stops it being read as a flag, so nothing here needs escaping.
      const res = await runCommand(
        "grep",
        ["-rn", "--include=*.js", "--exclude-dir=node_modules", "--", pattern, "."],
        targetDir
      );

      // grep: 0 = matched, 1 = no matches (normal), >=2 = real error.
      if (res.code === 1) {
        return JSON.stringify({
          ok: true,
          pattern,
          matches: [],
          note: "no matches",
        });
      }
      if (res.code !== 0) {
        return JSON.stringify({
          ok: false,
          stage: "grep",
          pattern,
          error: `grep failed (exit ${res.code})`,
          detail: res.stderr.trim() || undefined,
        });
      }

      const lines = res.stdout.split("\n").filter((l) => l.trim());
      const matches = lines
        .map(parseGrepLine)
        .filter((m): m is Match => m !== null)
        .slice(0, MAX_MATCHES);

      return JSON.stringify({
        ok: true,
        pattern,
        total: lines.length,
        returned: matches.length,
        truncated: lines.length > matches.length || undefined,
        matches,
      });
    },
  };
}
