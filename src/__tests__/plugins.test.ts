import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { VolidatorClient } from "../index";
import { VolidatorLangChainHandler } from "../plugins/agent-langchain";
import { createVercelAISDKCallback } from "../plugins/agent-vercel";

const TEST_KEY = "volidator-test-key-32-chars-xyzw";

async function decryptPayload(encrypted: string, rawKey: string): Promise<any> {
  const b64 = encrypted.slice(encrypted.indexOf(":") + 1);
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const iv = bytes.slice(0, 12);
  const ciphertext = bytes.slice(12);
  const keyHash = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(rawKey)
  );
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw", keyHash, { name: "AES-GCM" }, false, ["decrypt"]
  );
  const plain = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, cryptoKey, ciphertext
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

function makeFetchSpy() {
  let lastBody: any = null;
  const spy = vi.fn(async (_url: string, opts?: RequestInit) => {
    lastBody = JSON.parse(opts?.body as string);
    return { ok: true } as Response;
  });
  return { spy, getLastBody: () => lastBody };
}

describe("Volidator Plugins", () => {
  let fetchSpy: ReturnType<typeof makeFetchSpy>;

  beforeEach(() => {
    fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy.spy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  describe("VolidatorLangChainHandler", () => {
    it("intercepts tool execution start/end lifecycles and logs successful toolCall", async () => {
      const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });
      const handler = new VolidatorLangChainHandler(client, { actor: "test-langchain-agent", tenant: "t-1" });

      const runId = "test-run-123";
      await handler.handleToolStart({ name: "math_calculator" }, "2 + 2", runId);

      // Simulate some mock delay to verify map retrieval
      await new Promise((resolve) => setTimeout(resolve, 10));

      await handler.handleToolEnd("4", runId);

      const body = fetchSpy.getLastBody();
      expect(body).toBeDefined();

      const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
      expect(decrypted.action).toBe("agent.tool_call");
      expect(decrypted.actor).toBe("test-langchain-agent");
      expect(decrypted.metadata.toolName).toBe("math_calculator");
      expect(decrypted.metadata.toolInput).toEqual({ input: "2 + 2" });
      expect(decrypted.metadata.toolOutput).toEqual({ output: "4" });
      expect(decrypted.metadata.latencyMs).toBeGreaterThanOrEqual(10);
      expect(decrypted.metadata.success).toBe(true);
      expect(decrypted.metadata.eu_ai_act).toBe("Article 12");
    });

    it("intercepts tool execution errors and logs failed toolCall", async () => {
      const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });
      const handler = new VolidatorLangChainHandler(client, { actor: "test-langchain-agent" });

      const runId = "test-run-456";
      await handler.handleToolStart({ name: "unstable_tool" }, "crash me", runId);
      await handler.handleToolError(new Error("Division by zero"), runId);

      const body = fetchSpy.getLastBody();
      expect(body).toBeDefined();

      const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
      expect(decrypted.action).toBe("agent.tool_call");
      expect(decrypted.metadata.toolName).toBe("unstable_tool");
      expect(decrypted.metadata.toolInput).toEqual({ input: "crash me" });
      expect(decrypted.metadata.toolOutput).toEqual({ error: "Division by zero" });
      expect(decrypted.metadata.success).toBe(false);
    });
  });

  describe("createVercelAISDKCallback", () => {
    it("handles onStepFinish and logs successful tool runs", async () => {
      const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });
      const callback = createVercelAISDKCallback(client, { actor: "vercel-agent", tenant: "t-2" });

      // Mock Vercel AI SDK step completion event
      await callback({
        toolCalls: [
          { toolName: "weather_lookup", args: { city: "London" }, toolCallId: "c-1" }
        ],
        toolResults: [
          { toolName: "weather_lookup", args: { city: "London" }, toolCallId: "c-1", result: { temp: 18 } }
        ],
      });

      const body = fetchSpy.getLastBody();
      expect(body).toBeDefined();

      const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
      expect(decrypted.action).toBe("agent.tool_call");
      expect(decrypted.actor).toBe("vercel-agent");
      expect(decrypted.metadata.toolName).toBe("weather_lookup");
      expect(decrypted.metadata.toolInput).toEqual({ args: { city: "London" } });
      expect(decrypted.metadata.toolOutput).toEqual({ result: { temp: 18 } });
      expect(decrypted.metadata.success).toBe(true);
    });

    it("handles onStepFinish and logs failed tool calls", async () => {
      const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });
      const callback = createVercelAISDKCallback(client, { actor: "vercel-agent" });

      // Mock step with tool call but no matching tool result (e.g. aborted)
      await callback({
        toolCalls: [
          { toolName: "db_query", args: { table: "users" }, toolCallId: "c-2" }
        ],
        toolResults: [],
      });

      const body = fetchSpy.getLastBody();
      expect(body).toBeDefined();

      const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
      expect(decrypted.action).toBe("agent.tool_call");
      expect(decrypted.metadata.toolName).toBe("db_query");
      expect(decrypted.metadata.toolInput).toEqual({ args: { table: "users" } });
      expect(decrypted.metadata.toolOutput).toEqual({ error: "Execution failed or returned no result" });
      expect(decrypted.metadata.success).toBe(false);
    });
  });
});
