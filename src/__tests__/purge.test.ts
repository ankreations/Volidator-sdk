import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VolidatorClient } from "../index";

const TEST_KEY = "volidator-test-key-32-chars-xyzw";

function makeFetchSpy() {
  let lastUrl: string | null = null;
  let lastOpts: RequestInit | undefined = undefined;
  const spy = vi.fn(async (url: string, opts?: RequestInit) => {
    lastUrl = url;
    lastOpts = opts;
    return { ok: true, json: async () => ({ deletedCount: 5 }) } as Response;
  });
  return { spy, getLastUrl: () => lastUrl, getLastOpts: () => lastOpts };
}

describe("Volidator SDK GDPR Purge", () => {
  let fetchSpy: ReturnType<typeof makeFetchSpy>;

  beforeEach(() => {
    fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy.spy);
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("calls DELETE endpoint with correct path and headers", async () => {
    const client = new VolidatorClient({
      projectId: "prj_test_123",
      apiKey: "val_live_test_key",
      encryptionKey: TEST_KEY,
      endpoint: "http://localhost:8787"
    });

    const result = await client.purgeActorLogs("usr_alice");

    expect(result.deletedCount).toBe(5);
    expect(fetchSpy.spy).toHaveBeenCalledTimes(1);

    // Compute expected blind index to verify it matches
    const activeKeyBuffer = new TextEncoder().encode(TEST_KEY);
    const keyHash = await globalThis.crypto.subtle.digest("SHA-256", activeKeyBuffer);
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      keyHash,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );
    const signature = await globalThis.crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode("usr_alice")
    );
    const expectedBlindIndex = Array.from(new Uint8Array(signature))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");

    expect(fetchSpy.getLastUrl()).toBe(
      `http://localhost:8787/v1/projects/prj_test_123/actors/${expectedBlindIndex}`
    );
    expect(fetchSpy.getLastOpts()?.method).toBe("DELETE");
    expect(fetchSpy.getLastOpts()?.headers).toEqual({
      Authorization: "Bearer val_live_test_key",
    });
  });

  it("sends options in the body when provided", async () => {
    const client = new VolidatorClient({
      projectId: "prj_test_123",
      apiKey: "val_live_test_key",
      encryptionKey: TEST_KEY,
      endpoint: "http://localhost:8787"
    });

    const options = {
      sessionToken: "ast_session_123",
      webauthn: {
        challenge: "challenge_nonce",
        signature: "signature_data",
        authenticatorData: "auth_data",
        clientDataJSON: "client_json",
        credentialId: "cred_id",
        maxCreatedAt: "2026-07-09T00:00:00.000Z",
      }
    };

    const result = await client.purgeActorLogs("usr_alice", options);

    expect(result.deletedCount).toBe(5);
    expect(fetchSpy.spy).toHaveBeenCalledTimes(1);

    const opts = fetchSpy.getLastOpts();
    expect(opts?.method).toBe("DELETE");
    expect(opts?.headers).toEqual({
      Authorization: "Bearer val_live_test_key",
      "Content-Type": "application/json",
    });
    expect(JSON.parse(opts?.body as string)).toEqual({
      sessionToken: "ast_session_123",
      challenge: "challenge_nonce",
      signature: "signature_data",
      authenticatorData: "auth_data",
      clientDataJSON: "client_json",
      credentialId: "cred_id",
      maxCreatedAt: "2026-07-09T00:00:00.000Z",
    });
  });
});
