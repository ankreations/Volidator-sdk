import fs from "node:fs/promises";
import path from "node:path";

export interface FileFallbackOptions {
  // The directory where backup logs should be saved
  directory: string;
  // Suffix to append to the filename, defaults to "volidator-fallback"
  filenamePrefix?: string;
}

// Creates a concurrency-safe, daily-rolling filesystem fallback transport.
// Failed log write requests are appended to a running promise chain, ensuring atomic execution.
export function createFileFallbackTransport(
  options: FileFallbackOptions
): (payload: any, error: Error) => void {
  const dir = path.resolve(options.directory);
  const prefix = options.filenamePrefix || "volidator-fallback";

  // Sequential queue chain to prevent interleaving of concurrent writes
  let activePromise: Promise<void> = Promise.resolve();

  return (payload: any, error: Error) => {
    activePromise = activePromise.then(async () => {
      try {
        // Daily rolling filename based on UTC date
        const today = new Date().toISOString().split("T")[0]; // YYYY-MM-DD
        const targetFile = path.join(dir, `${prefix}-${today}.log`);

        // Ensure target directory exists
        await fs.mkdir(dir, { recursive: true });

        // Serialize log with timestamp and error message
        const logEntry = JSON.stringify({
          timestamp: new Date().toISOString(),
          error: error.message,
          payload,
        }) + "\n";

        await fs.appendFile(targetFile, logEntry, "utf-8");
      } catch (err) {
        console.error(
          `[Volidator] Failed to write local fallback backup: ${err instanceof Error ? err.message : String(err)
          }`
        );
      }
    });
  };
}
