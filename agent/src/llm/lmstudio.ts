import OpenAI from "openai";
import type { LlmClient } from "./client";
import type { Message, ToolDef, ToolCall, LlmResponse } from "./types";

type OpenAIMessage = OpenAI.Chat.Completions.ChatCompletionMessageParam;
type OpenAITool = OpenAI.Chat.Completions.ChatCompletionTool;

export class LMStudioClient implements LlmClient {
  private client: OpenAI;
  private model: string;

  constructor() {
    const baseURL = process.env.LMSTUDIO_BASE_URL ?? "http://localhost:1234/v1";
    const model = process.env.LMSTUDIO_MODEL ?? "qwen3-27b";

    this.client = new OpenAI({ baseURL, apiKey: "lm-studio" });
    this.model = model;
  }

  async complete(messages: Message[], tools: ToolDef[]): Promise<LlmResponse> {
    const completion = await this.client.chat.completions.create({
      model: this.model,
      messages: messages.map(toOpenAIMessage),
      tools: tools.length > 0 ? tools.map(toOpenAITool) : undefined,
    });

    const msg = completion.choices[0]?.message;

    const toolCalls: ToolCall[] = (msg?.tool_calls ?? []).map((tc) => {
      if (tc.type !== "function") {
        throw new Error(`Unsupported tool call type: ${tc.type}`);
      }
      return {
        id: tc.id,
        name: tc.function.name,
        arguments: parseArgs(tc.function.arguments),
      };
    });

    return { text: msg?.content ?? "", toolCalls, raw: completion };
  }
}

function toOpenAIMessage(m: Message): OpenAIMessage {
  switch (m.role) {
    case "system":
      return { role: "system", content: m.content };
    case "user":
      return { role: "user", content: m.content };
    case "tool":
      if (!m.toolCallId) throw new Error("tool message missing toolCallId");
      return { role: "tool", tool_call_id: m.toolCallId, content: m.content };
    case "assistant":
      if (m.toolCalls?.length) {
        return {
          role: "assistant",
          content: m.content || null,
          tool_calls: m.toolCalls.map((c) => ({
            id: c.id,
            type: "function",
            function: { name: c.name, arguments: JSON.stringify(c.arguments) },
          })),
        };
      }
      return { role: "assistant", content: m.content };
  }
}

function toOpenAITool(t: ToolDef): OpenAITool {
  return {
    type: "function",
    function: { name: t.name, description: t.description, parameters: t.parameters },
  };
}

function parseArgs(raw: string): Record<string, unknown> {
  try {
    return raw ? JSON.parse(raw) : {};
  } catch {
    throw new Error(`Model returned invalid JSON for tool arguments: ${raw}`);
  }
}
