import path from "node:path";
import { readFile } from "node:fs/promises";
import type { Tool } from "../../llm/types";

const MAX_CHARS = 5000;

/**
 * Resolve a model-supplied path inside the target directory, or null if it
 * escapes. This is the first tool that takes an arbitrary path from the model,
 * so traversal ('../../.env') has to be refused rather than sanitised.
 */
export function resolveInside(targetDir: string, input: string): string | null {
  const root = path.resolve(targetDir);
  const abs = path.resolve(root, input);
  if (abs !== root && !abs.startsWith(root + path.sep)) return null;
  return abs;
}

export function createReadFileTool(targetDir: string): Tool {
  return {
    definition: {
      name: "read_file",
      description:
        "Read a source file from the target project, given a path relative to the " +
        "project root (e.g. 'index.js'). Returns line-numbered contents so you can cite " +
        "file:line as evidence. Paths outside the project are refused.",
      parameters: {
        type: "object",
        properties: {
          path: {
            type: "string",
            description: "Path relative to the target project root, e.g. 'index.js'.",
          },
        },
        required: ["path"],
      },
    },
    async execute(rawArgs: Record<string, unknown>): Promise<string> {
      const input = typeof rawArgs.path === "string" ? rawArgs.path.trim() : "";
      if (!input) {
        return JSON.stringify({
          ok: false,
          stage: "args",
          error: "read_file requires a non-empty 'path' string",
        });
      }

      const abs = resolveInside(targetDir, input);
      if (!abs) {
        return JSON.stringify({
          ok: false,
          stage: "path",
          path: input,
          error: "path escapes the target directory — only files inside the project can be read",
        });
      }

      let raw: string;
      try {
        raw = await readFile(abs, "utf8");
      } catch (err) {
        return JSON.stringify({
          ok: false,
          stage: "read",
          path: input,
          error: (err as NodeJS.ErrnoException).message,
        });
      }

      const truncated = raw.length > MAX_CHARS;
      const body = truncated ? raw.slice(0, MAX_CHARS) : raw;
      const numbered = body
        .split("\n")
        .map((line, i) => `${i + 1}: ${line}`)
        .join("\n");

      return JSON.stringify({
        ok: true,
        path: input,
        lines: body.split("\n").length,
        truncated: truncated || undefined,
        content: truncated ? numbered + "\n…(truncated)…" : numbered,
      });
    },
  };
}
