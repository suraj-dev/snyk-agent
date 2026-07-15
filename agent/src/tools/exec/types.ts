export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface ExecFileError extends Error {
  code?: number | string;
  stdout?: string;
  stderr?: string;
}