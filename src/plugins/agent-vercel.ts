import type { VolidatorClient } from "../index";

export interface VercelAISDKHandlerConfig {
  /** The actor identifier (e.g., usr_alice, research-agent) to log the event under */
  actor: string;
  /** Optional tenant identifier */
  tenant?: string;
}

/**
 * createVercelAISDKCallback
 *
 * Returns an `onStepFinish` callback hook compatible with the Vercel AI SDK (`generateText` and `streamText`).
 * Automatically instruments and logs all tool invocations and outcomes.
 *
 * Note: Latency metrics are step-bound/approximated at the step level due to Vercel AI SDK's step-level event aggregation.
 */
export function createVercelAISDKCallback(
  client: VolidatorClient,
  config: VercelAISDKHandlerConfig,
): (event: any) => Promise<void> {
  return async (event: any): Promise<void> => {
    try {
      const toolResults = event.toolResults || [];
      const toolCalls = event.toolCalls || [];

      const loggedCalls = new Set<string>();

      // 1. Log all successful tool results
      for (const result of toolResults) {
        loggedCalls.add(result.toolCallId);
        await client.agent.toolCall({
          actor: config.actor,
          tenant: config.tenant,
          toolName: result.toolName || "unnamed_tool",
          toolInput: { args: result.args },
          toolOutput: { result: result.result },
          success: true,
        });
      }

      // 2. Log any tool calls that were aborted or failed to return a result
      for (const call of toolCalls) {
        if (!loggedCalls.has(call.toolCallId)) {
          await client.agent.toolCall({
            actor: config.actor,
            tenant: config.tenant,
            toolName: call.toolName || "unnamed_tool",
            toolInput: { args: call.args },
            toolOutput: { error: "Execution failed or returned no result" },
            success: false,
          });
        }
      }
    } catch (e) {
      console.warn("[Volidator] Failed to log step finish in Vercel AI SDK plugin", e);
    }
  };
}
