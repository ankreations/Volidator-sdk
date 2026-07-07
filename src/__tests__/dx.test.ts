import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { VolidatorClient } from "../index";

const TEST_KEY = "volidator-test-key-32-chars-xyzw";

describe("Volidator SDK DX Enhancements", () => {
  beforeEach(() => {
    vi.spyOn(console, "warn").mockImplementation(() => { });
    vi.spyOn(console, "error").mockImplementation(() => { });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  // ---------------------------------------------------------------------------
  // 1. Exponential Backoff Retries
  // ---------------------------------------------------------------------------
  describe("Log delivery retries", () => {
    it("retries on 500 and eventually succeeds", async () => {
      let callCount = 0;
      const fetchSpy = vi.fn(async () => {
        callCount++;
        if (callCount < 3) {
          return { ok: false, status: 500 } as Response;
        }
        return { ok: true, status: 200 } as Response;
      });
      vi.stubGlobal("fetch", fetchSpy);

      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
        maxRetries: 2, // 3 attempts total (0, 1, 2)
      });

      const success = await client.log({ actor: "test", action: "test" });
      expect(success).toBe(true);
      expect(callCount).toBe(3);
    });

    it("terminates immediately on 401 client error and does not retry", async () => {
      let callCount = 0;
      const fetchSpy = vi.fn(async () => {
        callCount++;
        return { ok: false, status: 401 } as Response;
      });
      vi.stubGlobal("fetch", fetchSpy);

      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
        maxRetries: 3,
      });

      const success = await client.log({ actor: "test", action: "test" });
      expect(success).toBe(false);
      expect(callCount).toBe(1);
    });

    it("triggers onDeliveryFailure callback on terminal failure", async () => {
      const fetchSpy = vi.fn(async () => {
        return { ok: false, status: 503 } as Response;
      });
      vi.stubGlobal("fetch", fetchSpy);

      let callbackPayload: any = null;
      let callbackError: any = null;

      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
        maxRetries: 1,
        onDeliveryFailure: (payload, err) => {
          callbackPayload = payload;
          callbackError = err;
        },
      });

      const logPayload = { actor: "test-actor", action: "failed-action" };
      const success = await client.log(logPayload);
      expect(success).toBe(false);
      expect(callbackPayload).toEqual(logPayload);
      expect(callbackError?.message).toContain("status 503");
    });
  });

  // ---------------------------------------------------------------------------
  // 2. Dev-mode warnings on metadata truncation
  // ---------------------------------------------------------------------------
  describe("Metadata truncation warnings", () => {
    it("emits console.warn on depth truncation in non-production environments", async () => {
      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
      });

      // Stub process.env.NODE_ENV
      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "development";

      // 6 levels deep object
      const deepMetadata = {
        l1: {
          l2: {
            l3: {
              l4: {
                l5: {
                  l6: "too_deep",
                },
              },
            },
          },
        },
      };

      // Call internal prepareLogEntry to check truncation logic
      const entry = await (client as any).prepareLogEntry({
        actor: "test",
        action: "test",
        metadata: deepMetadata,
      });

      // Verify the warning was printed
      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining("Log metadata exceeded maximum depth limit")
      );

      // Verify final payload was indeed truncated
      const decryptedMeta = await decryptPayload(entry.encryptedPayload, TEST_KEY);
      expect(decryptedMeta.metadata.l1.l2.l3.l4.l5).toBe("[Truncated - Depth Exceeded]");

      // Clean up
      process.env.NODE_ENV = originalEnv;
    });

    it("emits console.warn on string length truncation in non-production", async () => {
      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
      });

      const originalEnv = process.env.NODE_ENV;
      process.env.NODE_ENV = "development";

      const longString = "a".repeat(1005);
      const entry = await (client as any).prepareLogEntry({
        actor: "test",
        action: "test",
        metadata: { key: longString },
      });

      expect(console.warn).toHaveBeenCalledWith(
        expect.stringContaining("One or more log metadata string values exceeded")
      );

      const decryptedMeta = await decryptPayload(entry.encryptedPayload, TEST_KEY);
      expect(decryptedMeta.metadata.key.length).toBe(1003); // 1000 + "..."
      expect(decryptedMeta.metadata.key.endsWith("...")).toBe(true);

      process.env.NODE_ENV = originalEnv;
    });
  });

  // ---------------------------------------------------------------------------
  // 3. Batcher Convenience Client
  // ---------------------------------------------------------------------------
  describe("Batcher client", () => {
    it("stores logs and auto-flushes on count limit", async () => {
      const fetchSpy = vi.fn(async () => ({ ok: true } as Response));
      vi.stubGlobal("fetch", fetchSpy);

      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
      });

      const batcher = client.batcher({ autoFlushCount: 3 });
      expect(batcher.size()).toBe(0);

      batcher.push({ actor: "user1", action: "action1" });
      batcher.push({ actor: "user2", action: "action2" });
      expect(batcher.size()).toBe(2);
      expect(fetchSpy).not.toHaveBeenCalled();

      // Third push triggers count flush
      batcher.push({ actor: "user3", action: "action3" });
      // Flushes asynchronously, let's yield control to tick the queue
      await new Promise((resolve) => setTimeout(resolve, 100));

      expect(batcher.size()).toBe(0);
      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });

    it("flushes manually", async () => {
      const fetchSpy = vi.fn(async () => ({ ok: true } as Response));
      vi.stubGlobal("fetch", fetchSpy);

      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
      });

      const batcher = client.batcher();
      batcher.push({ actor: "user1", action: "action1" });
      expect(batcher.size()).toBe(1);

      const result = await batcher.flush();
      expect(result.accepted).toBe(1);
      expect(batcher.size()).toBe(0);
      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });
  });

  // ---------------------------------------------------------------------------
  // 4. generateEmbedToken Credential Overrides
  // ---------------------------------------------------------------------------
  describe("generateEmbedToken credential overrides", () => {
    it("uses constructor credentials when overrides are missing", async () => {
      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
        projectId: "proj_constructor",
        clientSecret: "secret_constructor",
      });

      const { token } = await client.generateEmbedToken({
        actorId: "actor123",
        scope: "actor",
      });

      const parts = token.split(".");
      const payload = JSON.parse(atob(parts[1]));
      expect(payload.pid).toBe("proj_constructor");
    });

    it("uses call-time overrides when provided", async () => {
      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
      });

      const { token } = await client.generateEmbedToken({
        actorId: "actor123",
        scope: "actor",
        projectId: "proj_override",
        clientSecret: "secret_override",
      });

      const parts = token.split(".");
      const payload = JSON.parse(atob(parts[1]));
      expect(payload.pid).toBe("proj_override");
    });

    it("throws if no credentials are provided anywhere", async () => {
      const client = new VolidatorClient({
        apiKey: "test",
        encryptionKey: TEST_KEY,
      });

      await expect(
        client.generateEmbedToken({
          actorId: "actor123",
          scope: "actor",
        })
      ).rejects.toThrow("requires projectId and clientSecret");
    });
  });
});

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
