import OpenAI from "openai";
import type { LlmClient } from "./client";
import type { Message, ToolDef, ToolCall, LlmResponse } from "./types";

type OpenAIMessage = OpenAI.Chat.Completions.ChatCompletionMessageParam;
type OpenAITool = OpenAI.Chat.Completions.ChatCompletionTool;

export class OpenRouterClient implements LlmClient {
  private client: OpenAI;
  private model: string;

  constructor() {
    const apiKey = process.env.OPENROUTER_API_KEY;
    if (!apiKey) throw new Error("OPENROUTER_API_KEY is not set");

    const model = process.env.OPENROUTER_MODEL;
    if (!model) throw new Error("OPENROUTER_MODEL is not set");

    this.client = new OpenAI({
      baseURL: "https://openrouter.ai/api/v1",
      apiKey,
      maxRetries: 3,
      defaultHeaders: {
        "HTTP-Referer": process.env.OPENROUTER_APP_URL ?? "",
        "X-Title": process.env.OPENROUTER_APP_NAME ?? "snyk-agent",
      },
    });
    this.model = model;
  }

  async complete(messages: Message[], tools: ToolDef[]): Promise<LlmResponse> {
    const completion = await this.withRetry(() =>
      this.client.chat.completions.create({
        model: this.model,
        messages: messages.map(toOpenAIMessage),
        tools: tools.length > 0 ? tools.map(toOpenAITool) : undefined,
        // @ts-expect-error — OpenRouter-specific
        models: [
          this.model,
          "z-ai/glm-4.5-air:free",
          "google/gemma-4-31b-it:free",
        ],
      }) as Promise<OpenAI.Chat.Completions.ChatCompletion>,
    );

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

  /** Retry on 429 / 5xx with exponential backoff + jitter. */
  private async withRetry<T>(fn: () => Promise<T>, attempts = 5): Promise<T> {
    let lastErr: unknown;
    for (let i = 0; i < attempts; i++) {
      try {
        return await fn();
      } catch (err: any) {
        lastErr = err;
        const status = err?.status;
        const retryable = status === 429 || (status >= 500 && status < 600);
        if (!retryable || i === attempts - 1) throw err;

        const backoff = Math.min(1000 * 2 ** i, 16000); // 1s,2s,4s,8s,16s cap
        const jitter = Math.random() * 400;
        const waitMs = backoff + jitter;
        console.warn(
          `LLM call rate-limited (status ${status}); retry ${i + 1}/${attempts - 1} in ${Math.round(waitMs)}ms`,
        );
        await new Promise((r) => setTimeout(r, waitMs));
      }
    }
    throw lastErr;
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
    function: {
      name: t.name,
      description: t.description,
      parameters: t.parameters,
    },
  };
}

function parseArgs(raw: string): Record<string, unknown> {
  try {
    return raw ? JSON.parse(raw) : {};
  } catch {
    throw new Error(`Model returned invalid JSON for tool arguments: ${raw}`);
  }
}
