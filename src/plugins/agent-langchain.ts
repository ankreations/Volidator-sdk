import { VolidatorClient } from "../index";

/**
 * Duck-typed interfaces to avoid runtime dependencies on LangChain core packages.
 */
export interface LangChainToolRun {
  name: string;
}

export interface LangChainHandlerConfig {
  /** The actor identifier (e.g., usr_alice, research-agent) to log the event under */
  actor: string;
  /** Optional tenant identifier */
  tenant?: string;
}

/**
 * VolidatorLangChainHandler
 * 
 * A callback handler to automatically instrument LangChain tool calls and log them to Volidator.
 * Avoids memory leaks by cleanly disposing of run trace contexts using .delete(runId).
 */
export class VolidatorLangChainHandler {
  private client: VolidatorClient;
  private actor: string;
  private tenant?: string;
  private runMap = new Map<string, { toolName: string; toolInput: any; startTime: number }>();

  constructor(client: VolidatorClient, config: LangChainHandlerConfig) {
    this.client = client;
    this.actor = config.actor;
    this.tenant = config.tenant;
  }

  /**
   * Called when a tool starts executing.
   */
  async handleToolStart(
    tool: LangChainToolRun,
    input: string,
    runId: string
  ): Promise<void> {
    this.runMap.set(runId, {
      toolName: tool.name || "unnamed_tool",
      toolInput: { input },
      startTime: Date.now(),
    });
  }

  /**
   * Called when a tool finishes executing successfully.
   */
  async handleToolEnd(output: string, runId: string): Promise<void> {
    const run = this.runMap.get(runId);
    if (!run) return;
    this.runMap.delete(runId); // Prevent memory leaks

    const latencyMs = Date.now() - run.startTime;
    try {
      await this.client.agent.toolCall({
        actor: this.actor,
        tenant: this.tenant,
        toolName: run.toolName,
        toolInput: run.toolInput,
        toolOutput: { output },
        latencyMs,
        success: true,
      });
    } catch (e) {
      console.warn("[Volidator] Failed to log toolCall in LangChain plugin", e);
    }
  }

  /**
   * Called when a tool execution fails with an error.
   */
  async handleToolError(err: any, runId: string): Promise<void> {
    const run = this.runMap.get(runId);
    if (!run) return;
    this.runMap.delete(runId); // Prevent memory leaks

    const latencyMs = Date.now() - run.startTime;
    const errorMessage = err instanceof Error ? err.message : String(err);
    try {
      await this.client.agent.toolCall({
        actor: this.actor,
        tenant: this.tenant,
        toolName: run.toolName,
        toolInput: run.toolInput,
        toolOutput: { error: errorMessage },
        latencyMs,
        success: false,
      });
    } catch (e) {
      console.warn("[Volidator] Failed to log toolCall error in LangChain plugin", e);
    }
  }
}
