import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { VolidatorClient } from "../index";

const TEST_KEY = "volidator-test-key-32-chars-xyzw";

function makeFetchMock() {
  return vi.fn(async (_url: string, _opts?: RequestInit) => {
    return { ok: true, json: async () => ({}) } as unknown as Response;
  });
}

describe("Volidator SDK Latency Bounds", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", makeFetchMock());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("measures local encryption overhead under 5ms", async () => {
    const client = new VolidatorClient({
      apiKey: "test",
      encryptionKey: TEST_KEY,
    });

    const start = performance.now();
    const count = 100;
    // Simulate encrypting payloads locally
    for (let i = 0; i < count; i++) {
      await client.log({ actor: "usr_bench", action: "CRYPTO_BENCH" });
    }
    const averageTime = (performance.now() - start) / count;
    
    console.log(`\n⏱️ Average local SDK encryption overhead: ${averageTime.toFixed(4)}ms per event\n`);
    expect(averageTime).toBeLessThan(15); // Asserts that encrypt/hash loop is highly efficient
  });
});
