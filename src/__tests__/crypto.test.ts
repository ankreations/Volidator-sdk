/**
 * Core cryptographic primitives — unit tests
 *
 * Tests: generateBlindIndex, encryptPayload, signHS256JWT, parseExpiry
 *
 * Strategy: cast `client` to `any` to access private methods directly.
 * This is intentional for a security-sensitive SDK — we want surgical
 * coverage of the underlying crypto, not just observable network behavior.
 *
 * Runtime: Node 20 — globalThis.crypto (WebCrypto) is available natively.
 * No mocking required.
 */

import { describe, it, expect } from "vitest";
import { VolidatorClient } from "../index";

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

/** A stable 32-char test key (length is arbitrary — the SDK SHA-256s it). */
const TEST_KEY = "volidator-test-key-32-chars-xyzw";

function makeClient(overrides: Record<string, any> = {}): VolidatorClient {
  return new VolidatorClient({
    apiKey: "test_api_key",
    encryptionKey: TEST_KEY,
    ...overrides,
  });
}

/**
 * Decrypt an `encryptedPayload` string produced by the SDK.
 * Format: `<keyId>:<base64(IV [12B] || ciphertext || auth-tag [16B])>`
 */
async function decryptPayload(encrypted: string, rawKey: string): Promise<any> {
  const colonIdx = encrypted.indexOf(":");
  const b64 = encrypted.slice(colonIdx + 1);

  // Convert base64 → bytes
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const iv = bytes.slice(0, 12);
  const ciphertext = bytes.slice(12);

  // Derive the same 32-byte key the SDK uses (SHA-256 of raw key string)
  const keyBytes = new TextEncoder().encode(rawKey);
  const keyHash = await globalThis.crypto.subtle.digest("SHA-256", keyBytes);
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    keyHash,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const plaintext = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    ciphertext
  );

  return JSON.parse(new TextDecoder().decode(plaintext));
}

/** Decode a base64url segment (JWT part) to a plain object. */
function decodeJwtPart(part: string): any {
  const base64 = part.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  return JSON.parse(Buffer.from(padded, "base64").toString("utf-8"));
}

// ---------------------------------------------------------------------------
// generateBlindIndex
// ---------------------------------------------------------------------------

describe("generateBlindIndex", () => {
  it("is deterministic — same input + same key → same output", async () => {
    const client = makeClient() as any;
    const key = await client._getHashedKey("v1");
    const idx1 = await client.generateBlindIndex("alice@example.com", key);
    const idx2 = await client.generateBlindIndex("alice@example.com", key);
    expect(idx1).toBe(idx2);
  });

  it("is sensitive to input — different values → different indexes", async () => {
    const client = makeClient() as any;
    const key = await client._getHashedKey("v1");
    const idx1 = await client.generateBlindIndex("alice@example.com", key);
    const idx2 = await client.generateBlindIndex("bob@example.com", key);
    expect(idx1).not.toBe(idx2);
  });

  it("is sensitive to key — same value, different key → different indexes", async () => {
    const clientA = makeClient({ encryptionKey: "key-a-32-chars-padded-xxxxxxxxx" }) as any;
    const clientB = makeClient({ encryptionKey: "key-b-32-chars-padded-xxxxxxxxx" }) as any;
    const keyA = await clientA._getHashedKey("v1");
    const keyB = await clientB._getHashedKey("v1");
    const idxA = await clientA.generateBlindIndex("same-value", keyA);
    const idxB = await clientB.generateBlindIndex("same-value", keyB);
    expect(idxA).not.toBe(idxB);
  });

  it("output is a hex string", async () => {
    const client = makeClient() as any;
    const key = await client._getHashedKey("v1");
    const idx = await client.generateBlindIndex("test-value", key);
    expect(idx).toMatch(/^[0-9a-f]+$/);
  });

  it("caches the hashed key — _getHashedKey called twice returns same Uint8Array", async () => {
    const client = makeClient() as any;
    const key1 = await client._getHashedKey("v1");
    const key2 = await client._getHashedKey("v1");
    expect(key1).toBe(key2); // same reference (from the cache)
  });
});

// ---------------------------------------------------------------------------
// encryptPayload
// ---------------------------------------------------------------------------

describe("encryptPayload", () => {
  it("returns a string prefixed with the active key ID", async () => {
    const client = makeClient() as any;
    const encrypted = await client.encryptPayload({ actor: "alice", action: "login" });
    expect(encrypted).toMatch(/^v1:/);
  });

  it("payload portion is valid base64", async () => {
    const client = makeClient() as any;
    const encrypted = await client.encryptPayload({ actor: "alice" });
    const b64 = encrypted.replace(/^v1:/, "");
    expect(() => atob(b64)).not.toThrow();
  });

  it("uses a different random IV each call — ciphertexts are non-deterministic", async () => {
    const client = makeClient() as any;
    const e1 = await client.encryptPayload({ actor: "alice" });
    const e2 = await client.encryptPayload({ actor: "alice" });
    expect(e1).not.toBe(e2);
  });

  it("round-trips correctly — decrypted output matches the original object", async () => {
    const client = makeClient() as any;
    const original = { actor: "alice", action: "login", target: "dashboard" };
    const encrypted = await client.encryptPayload(original);
    const decrypted = await decryptPayload(encrypted, TEST_KEY);
    expect(decrypted).toEqual(original);
  });

  it("uses the active key ID from a keyring", async () => {
    const client = new VolidatorClient({
      apiKey: "test",
      keyring: { v1: TEST_KEY, v2: "volidator-v2-key-32-chars-xyzwab" },
      activeEncryptionKeyId: "v2",
    }) as any;
    const encrypted = await client.encryptPayload({ actor: "bob" });
    expect(encrypted).toMatch(/^v2:/);
    const decrypted = await decryptPayload(encrypted, "volidator-v2-key-32-chars-xyzwab");
    expect(decrypted).toEqual({ actor: "bob" });
  });
});

// ---------------------------------------------------------------------------
// signHS256JWT
// ---------------------------------------------------------------------------

describe("signHS256JWT", () => {
  it("produces a valid 3-part dot-separated JWT", async () => {
    const client = makeClient() as any;
    const token = await client.signHS256JWT(
      { sub: "usr_123", iat: 1000, exp: 9999 },
      "my-secret"
    );
    const parts = token.split(".");
    expect(parts).toHaveLength(3);
  });

  it("header declares alg=HS256 and typ=JWT", async () => {
    const client = makeClient() as any;
    const token = await client.signHS256JWT({ sub: "test" }, "secret");
    const header = decodeJwtPart(token.split(".")[0]);
    expect(header).toEqual({ alg: "HS256", typ: "JWT" });
  });

  it("payload is faithfully encoded in the JWT", async () => {
    const client = makeClient() as any;
    const payload = { sub: "usr_123", pid: "proj_abc", iat: 1000, exp: 9999 };
    const token = await client.signHS256JWT(payload, "secret");
    const decoded = decodeJwtPart(token.split(".")[1]);
    expect(decoded).toMatchObject(payload);
  });

  it("different secrets produce different signatures", async () => {
    const client = makeClient() as any;
    const t1 = await client.signHS256JWT({ sub: "x" }, "secret-a");
    const t2 = await client.signHS256JWT({ sub: "x" }, "secret-b");
    expect(t1.split(".")[2]).not.toBe(t2.split(".")[2]);
  });

  it("same input + same secret → same token (deterministic)", async () => {
    const client = makeClient() as any;
    const payload = { sub: "x", iat: 1000, exp: 2000 };
    const t1 = await client.signHS256JWT(payload, "stable-secret");
    const t2 = await client.signHS256JWT(payload, "stable-secret");
    expect(t1).toBe(t2);
  });
});

// ---------------------------------------------------------------------------
// parseExpiry
// ---------------------------------------------------------------------------

describe("parseExpiry", () => {
  const cases: [string, number][] = [
    ["30s", 30],
    ["30m", 1800],
    ["2h", 7200],
    ["1d", 86400],
    ["7d", 604800],
  ];

  it.each(cases)('parses "%s" → %i seconds', (input, expected) => {
    const client = makeClient() as any;
    expect(client.parseExpiry(input)).toBe(expected);
  });

  it("falls back to 7200s for invalid input", () => {
    const client = makeClient() as any;
    expect(client.parseExpiry("invalid")).toBe(7200);
    expect(client.parseExpiry("")).toBe(7200);
    expect(client.parseExpiry("2x")).toBe(7200);
  });
});

// ---------------------------------------------------------------------------
// VolidatorClient constructor guards
// ---------------------------------------------------------------------------

describe("VolidatorClient constructor", () => {
  it("throws if no encryption key is provided", () => {
    expect(
      () => new VolidatorClient({ apiKey: "key" } as any)
    ).toThrow();
  });

  it("throws if keyring is provided without activeEncryptionKeyId", () => {
    expect(
      () =>
        new VolidatorClient({
          apiKey: "key",
          keyring: { v1: TEST_KEY },
        } as any)
    ).toThrow();
  });

  it("throws if keyring has more than 5 keys", () => {
    expect(
      () =>
        new VolidatorClient({
          apiKey: "key",
          keyring: { v1: "a", v2: "b", v3: "c", v4: "d", v5: "e", v6: "f" },
          activeEncryptionKeyId: "v1",
        })
    ).toThrow(/exceed 5/);
  });

  it("throws if activeEncryptionKeyId is not in the keyring", () => {
    expect(
      () =>
        new VolidatorClient({
          apiKey: "key",
          keyring: { v1: TEST_KEY },
          activeEncryptionKeyId: "v2",
        })
    ).toThrow(/must exist in the keyring/);
  });

  it("accepts encryptionKey shorthand and maps it to keyring[v1]", () => {
    const client = new VolidatorClient({
      apiKey: "key",
      encryptionKey: TEST_KEY,
    }) as any;
    expect(client.activeKeyId).toBe("v1");
    expect(client.keyring["v1"]).toBe(TEST_KEY);
  });
});
