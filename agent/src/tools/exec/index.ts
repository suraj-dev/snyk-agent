import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { CommandResult, ExecFileError } from "./types";

const execFileAsync = promisify(execFile);

function isExecFileError(err: unknown): err is ExecFileError {
  return err instanceof Error && ("stdout" in err || "code" in err);
}

/**
 * Run a command and capture output. A non-zero *exit code* is returned, not
 * thrown — callers decide what a given code means. Only a failure to launch the
 * process (e.g. binary not on PATH, which surfaces as a string code like ENOENT)
 * throws.
 */
export async function runCommand(
  file: string,
  args: string[],
  cwd: string,
  maxBuffer = 20 * 1024 * 1024
): Promise<CommandResult> {
  try {
    const { stdout, stderr } = await execFileAsync(file, args, { cwd, maxBuffer });
    return { code: 0, stdout, stderr };
  } catch (err: unknown) {
    // A numeric code means the process ran and exited non-zero — normal signal.
    if (isExecFileError(err) && typeof err.code === "number") {
      return { code: err.code, stdout: err.stdout ?? "", stderr: err.stderr ?? "" };
    }
    // A string code (ENOENT, etc.) means it never launched — genuine failure.
    throw err;
  }
}