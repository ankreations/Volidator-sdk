import { describe, it, expect, vi, beforeAll, afterAll } from "vitest";
import { VolidatorClient } from "../index";

const TEST_KEY = "volidator-test-key-32-chars-xyzw";

function makeClient(overrides: Record<string, any> = {}): VolidatorClient {
  return new VolidatorClient({
    apiKey: "test_api_key",
    encryptionKey: TEST_KEY,
    ...overrides,
  });
}

describe("Trace Ordering (Lamport Logical Timestamps)", () => {
  it("should increment the local clock on each prepareLogEntry", async () => {
    const client = makeClient();
    
    const entry1 = await (client as any).prepareLogEntry({ action: "test.action1" });
    const entry2 = await (client as any).prepareLogEntry({ action: "test.action2" });

    expect(entry1.logicalClock).toBe(1);
    expect(entry2.logicalClock).toBe(2);
  });

  it("should sync with incoming trace context clock using max(local, incoming) + 1", async () => {
    const client = makeClient();
    
    // Simulate incoming HTTP request with x-volidator-clock header = 10
    const mockRequest = {
      headers: {
        get: (name: string) => (name.toLowerCase() === "x-volidator-clock" ? "10" : null),
      },
    };

    const entry = await (client as any).prepareLogEntry({
      action: "test.action",
      req: mockRequest,
    });

    // Clock should update to max(0, 10) + 1 = 11
    expect(entry.logicalClock).toBe(11);
  });

  it("should run handlers inside logicalClockStore AsyncLocalStorage for context isolation", async () => {
    const client = makeClient();

    await VolidatorClient.logicalClockStore.run({ clock: 50 }, async () => {
      const entry1 = await (client as any).prepareLogEntry({ action: "test.action" });
      const entry2 = await (client as any).prepareLogEntry({ action: "test.action2" });
      
      // Thread context local clock should increment within store context: 50 -> 51 -> 52
      expect(entry1.logicalClock).toBe(51);
      expect(entry2.logicalClock).toBe(52);
    });

    // Outside store, fallback clock is still isolated (only incremented by our first test to 2)
    const entryOutside = await (client as any).prepareLogEntry({ action: "test.action" });
    expect(entryOutside.logicalClock).toBe(3);
  });
});

describe("Envelope Size Limits (Claim Check Pattern)", () => {
  let originalFetch: typeof globalThis.fetch;

  beforeAll(() => {
    originalFetch = globalThis.fetch;
  });

  afterAll(() => {
    globalThis.fetch = originalFetch;
  });

  it("should bypass claim checks for small payloads (under 30KB)", async () => {
    const client = makeClient();
    const entry = await (client as any).prepareLogEntry({
      action: "small.payload",
      metadata: { key: "small" },
    });

    expect(entry.isClaimCheck).toBe(false);
    expect(entry.encryptedPayload.startsWith("v1:")).toBe(true);
  });

  it("should upload encrypted payload to storage and return isClaimCheck true for large payloads (>30KB)", async () => {
    const client = makeClient();
    
    // Generate large metadata string (~35KB)
    const largeValue = "x".repeat(35000);
    const mockFetch = vi.fn().mockImplementation(() => Promise.resolve({ ok: true, status: 200 }));
    globalThis.fetch = mockFetch;

    const entry = await (client as any).prepareLogEntry({
      action: "large.payload",
      metadata: { key: largeValue },
    }, 100000); // Override metadata limit check to let us build a >30KB payload

    expect(entry.isClaimCheck).toBe(true);
    // encryptedPayload should be a 64-character content hash
    expect(entry.encryptedPayload).toMatch(/^[a-f0-9]{64}$/);
    
    // Verify R2 PUT upload was called
    expect(mockFetch).toHaveBeenCalled();
    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toContain("/v1/log/upload/");
    expect(options.method).toBe("PUT");
  });
});
