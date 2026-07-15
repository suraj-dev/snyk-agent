import type { Message, ToolDef, LlmResponse } from "./types";

/**
 * Provider-agnostic LLM interface. The agent loop depends only on this,
 * so swapping OpenRouter <-> Anthropic <-> anything else is a one-line change.
 */
export interface LlmClient {
  complete(messages: Message[], tools: ToolDef[]): Promise<LlmResponse>;
}