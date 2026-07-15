export type Role = "system" | "user" | "assistant" | "tool";

export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

export interface Message {
  role: Role;
  content: string;
  /** Present on assistant turns that requested one or more tools. */
  toolCalls?: ToolCall[];
  /** Present on tool-result turns; links the result to the originating call. */
  toolCallId?: string;
}

export interface ToolDef {
  name: string;
  description: string;
  /** JSON Schema object describing the tool's parameters. */
  parameters: Record<string, unknown>;
}

export interface Tool {
  /** The schema the LLM sees. */
  definition: ToolDef;
  /** Runs the tool. Receives parsed args, returns a string result for the model. */
  execute(args: Record<string, unknown>): Promise<string>;
}

export interface LlmResponse {
  /** Natural-language text (may be empty on a pure tool call). */
  text: string;
  /** Tool calls the model requested (empty if none). */
  toolCalls: ToolCall[];
  /** Raw provider response, for debugging. */
  raw: unknown;
}