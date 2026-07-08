/**
 * PII Redaction & Reference-Based Redaction — unit tests
 *
 * Verifies that `redactKeys` and `referenceKeys` correctly transform
 * log payloads before encryption. We decrypt the stored ciphertext to
 * assert the exact values written — this proves the protection works at
 * the storage layer, not just at the application layer.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VolidatorClient } from "../index";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

/** Captures the most recent body POSTed to the fake fetch. */
function makeFetchSpy() {
  let lastBody: any = null;
  const spy = vi.fn(async (_url: string, opts?: RequestInit) => {
    lastBody = JSON.parse(opts?.body as string);
    return { ok: true } as Response;
  });
  return { spy, getLastBody: () => lastBody };
}

// ---------------------------------------------------------------------------
// redactKeys — top-level fields
// ---------------------------------------------------------------------------

describe("redactKeys — top-level fields", () => {
  let fetchSpy: ReturnType<typeof makeFetchSpy>;

  beforeEach(() => {
    fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy.spy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("replaces actor with [REDACTED:actor] in encrypted payload", async () => {
    const client = new VolidatorClient({
      apiKey: "test",
      encryptionKey: TEST_KEY,
      redactKeys: ["actor"],
    });
    await client.log({ actor: "alice@company.com", action: "login" });
    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
    expect(decrypted.actor).toBe("[REDACTED:actor]");
  });

  it("replaces target with [REDACTED:target] in encrypted payload", async () => {
    const client = new VolidatorClient({
      apiKey: "test",
      encryptionKey: TEST_KEY,
      redactKeys: ["target"],
    });
    await client.log({ actor: "alice", action: "view", target: "report-q4" });
    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
    expect(decrypted.target).toBe("[REDACTED:target]");
  });

  it("does not redact fields not listed in redactKeys", async () => {
    const client = new VolidatorClient({
      apiKey: "test",
      encryptionKey: TEST_KEY,
      redactKeys: ["actor"],
    });
    await client.log({ actor: "alice", action: "login", target: "workspace-1" });
    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
    expect(decrypted.action).toBe("login");
    expect(decrypted.target).toBe("workspace-1");
  });

  it("still computes blind indexes from original PII — enabling search after redaction", async () => {
    // Two separate log calls with the same actor value but redactKeys set.
    // Both should produce the same actorBlindIndex (searchability preserved).
    const client = new VolidatorClient({
      apiKey: "test",
      encryptionKey: TEST_KEY,
      redactKeys: ["actor"],
    });
    await client.log({ actor: "alice@company.com", action: "login" });
    const idx1 = fetchSpy.getLastBody().actorBlindIndex;
    await client.log({ actor: "alice@company.com", action: "logout" });
    const idx2 = fetchSpy.getLastBody().actorBlindIndex;
    expect(idx1).toBe(idx2);
    expect(typeof idx1).toBe("string");
    expect(idx1.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// redactKeys — metadata fields
// ---------------------------------------------------------------------------

describe("redactKeys — metadata.fieldName notation", () => {
  let fetchSpy: ReturnType<typeof makeFetchSpy>;

  beforeEach(() => {
    fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy.spy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("replaces metadata.email with [REDACTED:email]", async () => {
    const client = new VolidatorClient({
      apiKey: "test",
      encryptionKey: TEST_KEY,
      redactKeys: ["metadata.email"],
    });
    await client.log({
      actor: "usr_123",
      action: "profile.update",
      metadata: { email: "alice@company.com", plan: "pro" },
    });
    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
    expect(decrypted.metadata.email).toBe("[REDACTED:email]");
    expect(decrypted.metadata.plan).toBe("pro"); // non-redacted field survives
  });
});

// ---------------------------------------------------------------------------
// referenceKeys — top-level fields (JIT Hydration)
// ---------------------------------------------------------------------------

describe("referenceKeys — top-level fields", () => {
  let fetchSpy: ReturnType<typeof makeFetchSpy>;

  beforeEach(() => {
    fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy.spy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("stores [REF:id] in encrypted payload instead of raw PII", async () => {
    const client = new VolidatorClient({
      apiKey: "test",
      encryptionKey: TEST_KEY,
      referenceKeys: ["actor"],
    });
    await client.log({
      actor: { id: "usr_890", pii: "alice@company.com" },
      action: "login",
    });
    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
    expect(decrypted.actor).toBe("[REF:usr_890]");
  });

  it("computes blind index from the PII value — not from the ref ID", async () => {
    const clientRef = new VolidatorClient({
      apiKey: "test",
      encryptionKey: TEST_KEY,
      referenceKeys: ["actor"],
    });
    const clientPlain = new VolidatorClient({
      apiKey: "test",
      encryptionKey: TEST_KEY,
    });

    // Log with referenceKeys
    await clientRef.log({
      actor: { id: "usr_890", pii: "alice@company.com" },
      action: "login",
    });
    const refBlindIndex = fetchSpy.getLastBody().actorBlindIndex;

    // Log with plain actor — same PII value
    await clientPlain.log({ actor: "alice@company.com", action: "login" });
    const plainBlindIndex = fetchSpy.getLastBody().actorBlindIndex;

    // They must match — proves blind index is computed from PII, not from [REF:id]
    expect(refBlindIndex).toBe(plainBlindIndex);
  });

  it("referenceKeys takes precedence over redactKeys for the same field", async () => {
    const client = new VolidatorClient({
      apiKey: "test",
      encryptionKey: TEST_KEY,
      referenceKeys: ["actor"],
      redactKeys: ["actor"],
    });
    await client.log({
      actor: { id: "usr_890", pii: "alice@company.com" },
      action: "login",
    });
    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
    // Reference should win — [REF:...] not [REDACTED:...]
    expect(decrypted.actor).toBe("[REF:usr_890]");
  });
});

// ---------------------------------------------------------------------------
// referenceKeys — metadata fields
// ---------------------------------------------------------------------------

describe("referenceKeys — metadata.fieldName notation", () => {
  let fetchSpy: ReturnType<typeof makeFetchSpy>;

  beforeEach(() => {
    fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy.spy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("stores [REF:id] for a metadata reference field", async () => {
    const client = new VolidatorClient({
      apiKey: "test",
      encryptionKey: TEST_KEY,
      referenceKeys: ["metadata.userId"],
    });
    await client.log({
      actor: "system",
      action: "report.generated",
      metadata: {
        userId: { id: "usr_42", pii: "bob@company.com" },
        reportType: "quarterly",
      },
    });
    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
    expect(decrypted.metadata.userId).toBe("[REF:usr_42]");
    expect(decrypted.metadata.reportType).toBe("quarterly");
  });
});

// ---------------------------------------------------------------------------
// Metadata size and depth guards
// ---------------------------------------------------------------------------

describe("metadata guardrails", () => {
  it("throws if serialized metadata exceeds 10 KB", async () => {
    const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });
    const hugeMeta: Record<string, string> = {};
    for (let i = 0; i < 200; i++) {
      hugeMeta[`key_${i}`] = "x".repeat(100);
    }
    await expect(
      client.log({ actor: "alice", action: "test", metadata: hugeMeta }),
    ).rejects.toThrow(/10KB/);
  });

  it("truncates deeply nested objects to [Truncated - Depth Exceeded]", async () => {
    const fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy.spy);

    const client = new VolidatorClient({ apiKey: "test", encryptionKey: TEST_KEY });
    const deep = { l1: { l2: { l3: { l4: { l5: "too deep" } } } } };
    await client.log({ actor: "alice", action: "test", metadata: { nested: deep } });

    const body = fetchSpy.getLastBody();
    const decrypted = await decryptPayload(body.encryptedPayload, TEST_KEY);
    // limitDepth starts at depth 1 for the top-level metadata object.
    // nested=depth1, l1=2, l2=3, l3=4, l4=5 → l4 is the last real value.
    // When depth > 5, the function returns the sentinel string.
    expect(decrypted.metadata.nested.l1.l2.l3.l4).toBe("[Truncated - Depth Exceeded]");

    vi.unstubAllGlobals();
  });
});
