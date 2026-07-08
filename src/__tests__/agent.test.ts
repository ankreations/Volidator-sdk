import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VolidatorClient } from "../index";

const TEST_KEY = "volidator-test-key-32-chars-xyzw";

async function decryptPayload(encrypted: string, rawKey: string): Promise<any> {
  const b64 = encrypted.slice(encrypted.indexOf(":") + 1);
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const iv = bytes.slice(0, 12);
  const ciphertext = bytes.slice(12);
  const keyHash = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(rawKey),
  );
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    keyHash,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const plain = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    ciphertext,
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

describe("VolidatorAgent Taxonomy", () => {
  let fetchSpy: ReturnType<typeof makeFetchSpy>;

  beforeEach(() => {
    fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy.spy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("logs toolCall with correct metadata and mapped parameters", async () => {
    const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });

    await client.agent.toolCall({
      actor: "research-agent",
      toolName: "web_search",
      toolInput: { q: "agent transparency" },
      toolOutput: { results: ["result 1"] },
      latencyMs: 120,
      success: true,
    });

    const body = fetchSpy.getLastBody();
    expect(body.actionBlindIndex).toBeDefined();

    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
    expect(decrypted.action).toBe("agent.tool_call");
    expect(decrypted.metadata.toolName).toBe("web_search");
    expect(decrypted.metadata.toolInput).toEqual({ q: "agent transparency" });
    expect(decrypted.metadata.toolOutput).toEqual({ results: ["result 1"] });
    expect(decrypted.metadata.latencyMs).toBe(120);
    expect(decrypted.metadata.success).toBe(true);
    expect(decrypted.metadata.eu_ai_act).toBe("Article 12");
    expect(decrypted.metadata.nist_ai_rmf).toBe("MANAGE 2.2");
  });

  it("logs decision with correct details", async () => {
    const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });

    await client.agent.decision({
      actor: "decision-engine",
      decision: "reject_loan",
      alternatives: ["approve_loan", "request_more_docs"],
      rationale: "FICO score below threshold",
      confidenceScore: 0.94,
      modelId: "claude-3-5-sonnet",
    });

    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);

    expect(decrypted.action).toBe("agent.decision");
    expect(decrypted.metadata.decision).toBe("reject_loan");
    expect(decrypted.metadata.alternatives).toEqual(["approve_loan", "request_more_docs"]);
    expect(decrypted.metadata.rationale).toBe("FICO score below threshold");
    expect(decrypted.metadata.confidenceScore).toBe(0.94);
    expect(decrypted.metadata.modelId).toBe("claude-3-5-sonnet");
    expect(decrypted.metadata.eu_ai_act).toBe("Article 12 & 13");
    expect(decrypted.metadata.nist_ai_rmf).toBe("GOVERN 1.7");
  });

  it("logs escalation requiring human review", async () => {
    const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });

    await client.agent.escalation({
      actor: "agent-alpha",
      reason: "high-value transaction confirmation required",
      urgency: "high",
      blockedAction: "transfer_funds",
    });

    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);

    expect(decrypted.action).toBe("agent.escalation");
    expect(decrypted.metadata.reason).toBe("high-value transaction confirmation required");
    expect(decrypted.metadata.urgency).toBe("high");
    expect(decrypted.metadata.blockedAction).toBe("transfer_funds");
    expect(decrypted.metadata.eu_ai_act).toBe("Article 14");
    expect(decrypted.metadata.nist_ai_rmf).toBe("GOVERN 5.1");
  });

  it("logs anomalies correctly", async () => {
    const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });

    await client.agent.anomaly({
      actor: "guardrail-agent",
      description: "suspected prompt injection payload detected",
      severity: "critical",
      anomalyType: "prompt_injection",
    });

    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);

    expect(decrypted.action).toBe("agent.anomaly");
    expect(decrypted.metadata.description).toBe("suspected prompt injection payload detected");
    expect(decrypted.metadata.severity).toBe("critical");
    expect(decrypted.metadata.anomalyType).toBe("prompt_injection");
    expect(decrypted.metadata.eu_ai_act).toBe("Article 9");
    expect(decrypted.metadata.nist_ai_rmf).toBe("MANAGE 2.4");
  });

  it("logs safety refusal", async () => {
    const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });

    await client.agent.refusal({
      actor: "safety-guard",
      refusedInstruction: "write code to exploit server",
      reason: "harmful content generation blocked",
      policyViolated: "anti-malware-guideline",
    });

    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);

    expect(decrypted.action).toBe("agent.refusal");
    expect(decrypted.metadata.refusedInstruction).toBe("write code to exploit server");
    expect(decrypted.metadata.reason).toBe("harmful content generation blocked");
    expect(decrypted.metadata.policyViolated).toBe("anti-malware-guideline");
    expect(decrypted.metadata.eu_ai_act).toBe("Article 5");
    expect(decrypted.metadata.nist_ai_rmf).toBe("GOVERN 1.1");
  });

  it("logs execution handoffs", async () => {
    const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });

    await client.agent.handoff({
      actor: "orchestrator",
      toAgentId: "coder-agent",
      instruction: "write landing page css",
      agentContext: { theme: "dark" },
    });

    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);

    expect(decrypted.action).toBe("agent.handoff");
    expect(decrypted.metadata.toAgentId).toBe("coder-agent");
    expect(decrypted.metadata.instruction).toBe("write landing page css");
    expect(decrypted.metadata.agentContext).toEqual({ theme: "dark" });
    expect(decrypted.metadata.eu_ai_act).toBe("Article 12");
    expect(decrypted.metadata.nist_ai_rmf).toBe("MAP 1.6");
  });

  it("allows metadata size up to 5MB on agent pathways using Claim Check R2", async () => {
    const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });

    // Create large 250KB metadata object
    const largeObj: Record<string, string> = {};
    for (let i = 0; i < 250; i++) {
      largeObj[`key_${i}`] = "x".repeat(1000);
    }

    await expect(
      client.agent.toolCall({
        actor: "test",
        toolName: "huge-runner",
        success: true,
        toolOutput: largeObj,
      }),
    ).resolves.toBe(true);

    // Verify it still throws if it goes past the 5MB hard limit
    const hugeObj: Record<string, string> = {};
    for (let i = 0; i < 5200; i++) {
      hugeObj[`key_${i}`] = "x".repeat(1000);
    }
    await expect(
      client.agent.toolCall({
        actor: "test",
        toolName: "huge-runner",
        success: true,
        toolOutput: hugeObj,
      }),
    ).rejects.toThrow(/exceeds the 5MB hard limit/);
  });
});

describe("VolidatorClient Batch Logging", () => {
  let fetchSpy: ReturnType<typeof makeFetchSpy>;

  beforeEach(() => {
    fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy.spy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("prepares and sends multiple log entries in a single request", async () => {
    const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });

    const res = await client.logBatch([
      { actor: "agent-1", action: "test-action-1" },
      { actor: "agent-2", action: "test-action-2" },
    ]);

    expect(res).toEqual({ accepted: 2, rejected: 0 });
    expect(fetchSpy.spy).toHaveBeenCalledTimes(1);

    const fetchArgs = fetchSpy.spy.mock.calls[0];
    expect(fetchArgs[0]).toMatch(/\/v1\/logs\/batch$/);

    const body = fetchSpy.getLastBody();
    expect(body.logs).toHaveLength(2);

    const e1 = await decryptPayload(body.logs[0].encryptedPayload, TEST_KEY);
    const e2 = await decryptPayload(body.logs[1].encryptedPayload, TEST_KEY);
    expect(e1.actor).toBe("agent-1");
    expect(e1.action).toBe("test-action-1");
    expect(e2.actor).toBe("agent-2");
    expect(e2.action).toBe("test-action-2");
  });
});
