import { describe, expect, it } from "vitest";
import fs from "node:fs/promises";
import path from "node:path";
import { createFileFallbackTransport } from "../fallback-file";

describe("SDK Local Fallback File Transport Tests", () => {
  it("writes concurrent failed logs sequentially without interleaving/corruption", async () => {
    const tempDir = path.resolve(__dirname, "temp-fallback");

    // Initialize the file transport
    const fallbackTransport = createFileFallbackTransport({
      directory: tempDir,
      filenamePrefix: "test-fallback",
    });

    const error = new Error("Connection failed");
    const count = 50;

    // Trigger 50 concurrent writes
    for (let i = 0; i < count; i++) {
      const payload = { eventId: i, message: "Log event message " + i };
      fallbackTransport(payload, error);
    }

    // Wait for all writes to conclude sequentially in the promise queue
    await new Promise((resolve) => setTimeout(resolve, 300));

    // Get daily date suffix
    const today = new Date().toISOString().split("T")[0];
    const logFile = path.join(tempDir, "test-fallback-" + today + ".log");

    // Assert file exists
    const fileExists = await fs
      .stat(logFile)
      .then(() => true)
      .catch(() => false);
    expect(fileExists).toBe(true);

    // Read and parse file content
    const content = await fs.readFile(logFile, "utf-8");
    const lines = content.trim().split("\n");

    expect(lines.length).toBe(count);

    // Verify each line is a valid parseable JSON object
    for (let i = 0; i < lines.length; i++) {
      const entry = JSON.parse(lines[i]);
      expect(entry.error).toBe("Connection failed");
      expect(entry.payload.eventId).toBe(i);
      expect(entry.timestamp).toBeDefined();
    }

    // Clean up
    await fs.rm(logFile, { force: true });
    await fs.rmdir(tempDir).catch(() => {});
  });
});
