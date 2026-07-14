import { beforeEach, describe, expect, it, vi } from "vitest";
import worker from "../../../../apps/ingestion-worker/src/index";
import { VolidatorClient } from "../index";

// Mock D1 Database as plain JS functions so they are immune to resetAllMocks
const mockD1 = {
  prepare: () => ({
    bind: () => ({
      get: async () => ({
        id: "proj_123",
        tier: "pro",
        credentialClass: "agent",
        credentialOwnerId: null,
        currentPeriodProofs: 0,
      }),
      all: async () => ({ results: [] }),
      run: async () => ({ success: true }),
    }),
    get: async () => ({
      id: "proj_123",
      tier: "pro",
      credentialClass: "agent",
      credentialOwnerId: null,
      currentPeriodProofs: 0,
    }),
    all: async () => ({ results: [] }),
    run: async () => ({ success: true }),
  }),
  batch: async () => [],
  exec: async () => ({ success: true }),
};

const mockKv = {
  get: async (key: string) => {
    if (key.includes("chain:")) {
      return "0".repeat(64);
    }
    return JSON.stringify({
      projectId: "proj_123",
      tier: "pro",
      credentialClass: "agent",
      credentialOwnerId: null,
    });
  },
  put: async () => { },
};

const mockQueue = {
  send: async () => { },
};

const mockLargePayloadBucket = {
  put: async () => { },
};

const mockRateLimiter = {
  limit: async () => ({ success: true }),
};

const mockEnv = {
  DB: mockD1 as any,
  KV_CACHE: mockKv as any,
  PROOF_BATCH_QUEUE: mockQueue as any,
  DB_INGEST_QUEUE: mockQueue as any,
  LARGE_PAYLOAD_BUCKET: mockLargePayloadBucket as any,
  RATE_LIMITER: mockRateLimiter as any,
  DEV_MODE: true,
};

const mockCtx = {
  waitUntil: async (promise: Promise<any>) => {
    try {
      await promise;
    } catch (e) {
      // Ignored in tests
    }
  },
};

describe("Certifying Proxy Edge Endpoint Tests", () => {
  beforeEach(() => {
    vi.resetAllMocks();
  });

  it("returns 401 Unauthorized if no API key is supplied", async () => {
    const req = new Request("http://localhost/v1/proxy", {
      method: "POST",
      body: JSON.stringify({ target: "https://example.com" }),
      headers: { "Content-Type": "application/json" },
    });
    const res = await worker.fetch(req, mockEnv, mockCtx as any);
    expect(res.status).toBe(401);
    const data: any = await res.json();
    expect(data.error).toContain("Unauthorized");
  });

  it("returns 400 if X-Volidator-Encryption-Key is missing", async () => {
    const req = new Request("http://localhost/v1/proxy", {
      method: "POST",
      body: JSON.stringify({ target: "https://example.com" }),
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer val_agent_bb48417cb42cb26fc88106247d",
      },
    });
    const res = await worker.fetch(req, mockEnv, mockCtx as any);
    expect(res.status).toBe(400);
    const data: any = await res.json();
    expect(data.error).toContain("X-Volidator-Encryption-Key");
  });

  it("returns 400 on SSRF blocked private IP targets", async () => {
    const req = new Request("http://localhost/v1/proxy", {
      method: "POST",
      body: JSON.stringify({ target: "http://192.168.1.100/api" }),
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer val_agent_bb48417cb42cb26fc88106247d",
        "X-Volidator-Encryption-Key": "test-key-32-chars-xyz-abcdefghij",
      },
    });
    const res = await worker.fetch(req, mockEnv, mockCtx as any);
    expect(res.status).toBe(400);
    const data: any = await res.json();
    expect(data.error).toContain("SSRF");
  });

  it("returns 400 on loopback target URL", async () => {
    const req = new Request("http://localhost/v1/proxy", {
      method: "POST",
      body: JSON.stringify({ target: "http://localhost/something" }),
      headers: {
        "Content-Type": "application/json",
        "Authorization": "Bearer val_agent_bb48417cb42cb26fc88106247d",
        "X-Volidator-Encryption-Key": "test-key-32-chars-xyz-abcdefghij",
      },
    });
    const res = await worker.fetch(req, mockEnv, mockCtx as any);
    expect(res.status).toBe(400);
  });

  it("successfully proxies and encrypts a DeepSeek chat completion request", async () => {
    const mockResponseBody = JSON.stringify({
      id: "chatcmpl-123",
      choices: [{ message: { role: "assistant", content: "Hello! How can I help you today?" } }],
    });

    const originalFetch = global.fetch;
    const fetchSpy = vi.fn(async (url: string, init?: RequestInit) => {
      expect(url).toBe("https://api.deepseek.com/chat/completions");
      expect(init?.method).toBe("POST");
      expect(init?.headers instanceof Headers).toBe(true);
      const headers = init?.headers as Headers;
      expect(headers.has("x-volidator-encryption-key")).toBe(false);
      expect(headers.has("x-volidator-api-key")).toBe(false);
      return new Response(mockResponseBody, {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    global.fetch = fetchSpy as any;

    try {
      const req = new Request("http://localhost/v1/proxy", {
        method: "POST",
        body: JSON.stringify({
          target: "https://api.deepseek.com/chat/completions",
          payload: {
            model: "deepseek-chat",
            messages: [{ role: "user", content: "Hi" }],
          },
        }),
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Bearer val_agent_bb48417cb42cb26fc88106247d",
          "X-Volidator-Encryption-Key": "test-key-32-chars-xyz-abcdefghij",
        },
      });

      const res = await worker.fetch(req, mockEnv, mockCtx as any);
      expect(res.status).toBe(200);
      const data: any = await res.json();
      expect(data.id).toBe("chatcmpl-123");
      expect(fetchSpy).toHaveBeenCalled();
    } finally {
      global.fetch = originalFetch;
    }
  });

  it("VolidatorClient.verifyProof validates untampered payloads and rejects tampered ones", async () => {
    const payload = { actor: "usr_1", action: "test" };
    const sibling = "a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4";

    const encoder = new TextEncoder();
    const jsonStr = JSON.stringify(payload);
    const payloadHashBuf = await crypto.subtle.digest("SHA-256", encoder.encode(jsonStr));
    const computedPayloadHash = Array.from(new Uint8Array(payloadHashBuf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    const combined = computedPayloadHash + sibling;
    const rootBuf = await crypto.subtle.digest("SHA-256", encoder.encode(combined));
    const merkleRoot = Array.from(new Uint8Array(rootBuf))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    const proof = {
      merkleRoot,
      merklePathJson: JSON.stringify([sibling]),
    };

    const isVerified = await VolidatorClient.verifyProof(payload, proof);
    expect(isVerified).toBe(true);

    const tamperedPayload = { actor: "usr_1", action: "test-tampered" };
    const isTamperedVerified = await VolidatorClient.verifyProof(tamperedPayload, proof);
    expect(isTamperedVerified).toBe(false);
  });
});
