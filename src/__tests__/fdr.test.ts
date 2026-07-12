import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VolidatorClient } from "../index";
import { wrapVectorStore } from "../plugins/fdr-vector";
import { gunzipSync } from "node:zlib";

const TEST_KEY = "volidator-test-key-32-chars-xyzw";

function makeFetchSpy() {
  let lastBody: any = null;
  let lastUrl: string | null = null;
  const spy = vi.fn(async (url: string, opts?: RequestInit) => {
    lastUrl = url;
    if (opts?.body) {
      lastBody = JSON.parse(opts.body as string);
    }
    return {
      ok: true,
      json: async () => ({
        ledgerId: "fdr_mock_ledger_id",
        chainHash: "fdr_mock_chain_hash",
        r2Key: "fdr_mock_r2_key",
        payloadHash: "fdr_mock_payload_hash",
      }),
    } as Response;
  });
  return { spy, getLastBody: () => lastBody, getLastUrl: () => lastUrl };
}

describe("Volidator FDR (Flight Data Recorder) & Bi-temporal Vector Memory", () => {
  let fetchSpy: ReturnType<typeof makeFetchSpy>;

  beforeEach(() => {
    fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy.spy);
    if (typeof process !== "undefined") {
      delete process.env.VOLIDATOR_REPLAY_MODE;
    }
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    if (typeof process !== "undefined") {
      delete process.env.VOLIDATOR_REPLAY_MODE;
    }
  });

  describe("VolidatorFdr Core Lifecycle", () => {
    it("throws if calling FDR methods without fdr: { enabled: true }", () => {
      const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });
      expect(() => client.fdr.createRun("run-1", "proj-1")).toThrow(/FDR is not enabled/);
    });

    it("captures tool calls, applies allowList, hashes arguments, and builds evidence bundle correctly", async () => {
      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
        fdr: { enabled: true },
      });

      const runCtx = client.fdr.createRun("run-1", "proj-1");

      const testTool = client.fdr.wrapToolForVCR(
        "test_tool",
        async (args: { input: string; secret: string }) => {
          return { response: `Processed ${args.input}` };
        },
        runCtx,
        { allowList: ["input"] }
      );

      // Execute tool
      const result = await testTool({ input: "hello", secret: "super_secret_token" });
      expect(result).toEqual({ response: "Processed hello" });

      // Check runCtx accumulator
      expect(runCtx.tools.length).toBe(1);
      const record = runCtx.tools[0];
      expect(record.toolName).toBe("test_tool");
      expect(record.seq).toBe(1);
      expect(record.args).toEqual({ input: "hello" }); // secret scrubbed!
      expect(record.args.secret).toBeUndefined();
      expect(record.output).toEqual({ response: "Processed hello" });
      expect(record.argsHash).toBeDefined();

      // Capture prompt and provider alibi
      await client.fdr.captureSystemPrompt(runCtx, "System instructions...");
      client.fdr.captureProviderAlibi(runCtx, {
        modelId: "gpt-4o-test",
        systemFingerprint: "fp_123",
        seed: 42,
      });

      expect(runCtx.systemPrompt).toBe("System instructions...");
      expect(runCtx.systemPromptHash).toBeDefined();
      expect(runCtx.providerAlibi).toEqual({
        modelId: "gpt-4o-test",
        systemFingerprint: "fp_123",
        seed: 42,
      });

      // Commit run and upload
      const commitRes = await client.fdr.commitRun(runCtx);
      expect(commitRes.chainHash).toBe("fdr_mock_chain_hash");

      // Verify what was posted
      const body = fetchSpy.getLastBody();
      expect(body).toBeDefined();
      expect(body.runId).toBe("run-1");
      expect(body.projectId).toBe("proj-1");
      expect(body.payloadHash).toBeDefined();
      expect(body.payloadB64gz).toBeDefined();

      // Decompress and verify bundle contents
      const gzippedBytes = Buffer.from(body.payloadB64gz, "base64");
      const decompressed = gunzipSync(gzippedBytes).toString("utf-8");
      const bundle = JSON.parse(decompressed);

      expect(bundle.version).toBe(1);
      expect(bundle.runId).toBe("run-1");
      expect(bundle.projectId).toBe("proj-1");
      expect(bundle.systemPrompt).toBe("System instructions...");
      expect(bundle.providerAlibi.modelId).toBe("gpt-4o-test");
      expect(bundle.tools.length).toBe(1);
      expect(bundle.tools[0].toolName).toBe("test_tool");
    });
  });

  describe("FDR Replay Mode", () => {
    it("intercepts tool execution and returns cached output in replay mode without executing original tool", async () => {
      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
        fdr: { enabled: true },
      });

      const runCtx = client.fdr.createRun("run-2", "proj-2");

      // 1. Capture tool output first to get the correct argsHash key
      const testTool = client.fdr.wrapToolForVCR(
        "replay_tool",
        async (_args: { query: string }) => {
          return { data: "live_data" };
        },
        runCtx,
        { allowList: ["query"] }
      );

      await testTool({ query: "pricing" });
      const argsHash = runCtx.tools[0].argsHash;

      // 2. Load the cached replay store in the FDR namespace and enable replay mode env
      const cachedResponses = new Map<string, any>();
      cachedResponses.set(argsHash, { data: "historical_cached_data" });
      client.fdr.loadReplayStore(cachedResponses);

      if (typeof process !== "undefined") {
        process.env.VOLIDATOR_REPLAY_MODE = "1";
      }

      // Re-create tool with a mock function that would throw if executed
      const replayTool = client.fdr.wrapToolForVCR(
        "replay_tool",
        async () => {
          throw new Error("Should not execute original tool in replay mode!");
        },
        runCtx,
        { allowList: ["query"] }
      );

      // Execute tool inside mock simulation. Should fetch from cache.
      const replayResult = await replayTool({ query: "pricing" });
      expect(replayResult).toEqual({ data: "historical_cached_data" });
    });
  });

  describe("Bi-Temporal Vector Store Middleware", () => {
    const mockDb = {
      upsert: vi.fn(),
      delete: vi.fn(),
      query: vi.fn(),
    };

    it("stamps docs with valid_from/valid_to and formats pgvector updates/deletes", async () => {
      const wrapped = wrapVectorStore(mockDb, {
        mode: "pgvector",
        namespace: "test-ns",
        validFromField: "valid_from_ts",
        validToField: "valid_to_ts",
      });

      // Test Upsert
      await wrapped.upsert([{ id: "v-1", values: [0.1, 0.2], metadata: { text: "hello" } }]);
      expect(mockDb.upsert).toHaveBeenCalled();
      const firstArg = mockDb.upsert.mock.calls[0][0];
      expect(firstArg[0].metadata.valid_from_ts).toBeDefined();
      expect(firstArg[0].metadata.valid_to_ts).toBeNull();

      // Test pgvector Delete (converts to soft-delete upsert of metadata)
      await wrapped.delete(["v-1"], "Audit archive purge");
      const deleteArg = mockDb.upsert.mock.calls[1][0];
      expect(deleteArg[0].id).toBe("v-1");
      expect(deleteArg[0].metadata.valid_to_ts).toBeDefined();
      expect(deleteArg[0].metadata._vld_delete_reason).toBe("Audit archive purge");
    });

    it("injects temporal validity checks to search queries based on asOf timestamp", async () => {
      const wrapped = wrapVectorStore(mockDb, {
        mode: "hosted",
        namespace: "test-ns",
      });

      const asOf = 1700000000000;
      await wrapped.query({ vector: [0.1], filter: { category: "financials" } }, asOf);
      expect(mockDb.query).toHaveBeenCalled();
      const queryArg = mockDb.query.mock.calls[0][0];
      expect(queryArg.filter.category).toBe("financials");
      expect(queryArg.filter._vld_from).toEqual({ $lte: asOf });
      expect(queryArg.filter.$or).toEqual([
        { _vld_to: { $gt: asOf } },
        { _vld_to: null },
      ]);
    });
  });
});
