/**
 * @volidator/node — FDR VCR (Flight Data Recorder — Tool Execution VCR)
 *
 * Provides `wrapToolForVCR()`: a tool-layer interceptor that captures the exact
 * input arguments and output of any agent tool execution and ships the evidence
 * bundle to Volidator's FDR ingestion endpoint.
 *
 * Key design decisions:
 *  - Intercepts at the tool abstraction layer (not HTTP), making it protocol-agnostic
 *    (works for HTTP, MCP stdio, subprocess, browser automation, etc.).
 *  - Uses an allow-list to scrub secrets before serialization — transport-layer
 *    credentials never enter the capture path.
 *  - Gzips the payload using the native CompressionStream API (available in
 *    Node.js ≥ 18 and all Cloudflare Workers runtimes).
 *  - In VOLIDATOR_REPLAY_MODE, routes tool calls to the local VCR cache instead
 *    of executing the real function.
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** The provider alibi captures deterministic model configuration metadata. */
export interface FdrProviderAlibi {
  /** The exact model identifier string (e.g. "gpt-4o-2024-08-06") */
  modelId: string;
  /**
   * OpenAI system_fingerprint — a per-model-deployment identifier that changes
   * when the underlying serving infrastructure is modified.
   * @see https://platform.openai.com/docs/api-reference/chat/object
   */
  systemFingerprint?: string;
  /**
   * The random seed used for generation. Only meaningful when temperature = 0
   * and supported by the provider.
   */
  seed?: number;
  /**
   * Sampled temperature. Stored for transparency; does not guarantee replay.
   */
  temperature?: number;
}

/** A single captured tool execution record stored inside an FDR evidence bundle. */
export interface FdrToolRecord {
  /** Monotonically incrementing index within the run. Used for sequential VCR playback. */
  seq: number;
  toolName: string;
  /** SHA-256 hex of JSON.stringify(args) — used as VCR lookup key during replay. */
  argsHash: string;
  /** The scrubbed, allow-listed input arguments. */
  args: Record<string, unknown>;
  /** The raw output returned by the tool. */
  output: unknown;
  /** Wall-clock execution duration in milliseconds. */
  latencyMs: number;
  capturedAt: number;
}

/** The full FDR evidence bundle stored in R2 for a single agent run. */
export interface FdrEvidenceBundle {
  version: 1;
  runId: string;
  projectId: string;
  /** SHA-256 of the plaintext system prompt — proves the exact instruction set. */
  systemPromptHash?: string;
  /** Verbatim system prompt text (encrypted separately). */
  systemPrompt?: string;
  providerAlibi?: FdrProviderAlibi;
  tools: FdrToolRecord[];
  committedAt: number;
}

/** Configuration for the VCR wrapper. */
export interface VcrWrapOptions {
  /**
   * Explicit allow-list of argument keys to include in the captured record.
   * Any key not in this list is dropped before serialization.
   * This prevents API keys, bearer tokens, and other transport-layer secrets
   * from entering the evidence bundle.
   *
   * @example allowList: ['ticker', 'price', 'timestamp']
   */
  allowList?: string[];
}

/** Internal context accumulated during an FDR-instrumented run. */
export interface FdrRunContext {
  runId: string;
  projectId: string;
  tools: FdrToolRecord[];
  systemPromptHash?: string;
  systemPrompt?: string;
  providerAlibi?: FdrProviderAlibi;
  _seq: number;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Computes a SHA-256 hex digest of a UTF-8 string using the native WebCrypto API.
 * Works in Node.js ≥ 18 and Cloudflare Workers runtimes.
 */
async function sha256hex(text: string): Promise<string> {
  const buf = new TextEncoder().encode(text);
  const hashBuf = await globalThis.crypto.subtle.digest("SHA-256", buf.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Applies the allow-list filter to a raw args object.
 * Returns a new object containing only the keys present in `allowList`.
 * If `allowList` is undefined or empty, the full args object is returned as-is.
 */
function scrubArgs(
  args: Record<string, unknown>,
  allowList?: string[],
): Record<string, unknown> {
  if (!allowList || allowList.length === 0) {
    return args;
  }
  const scrubbed: Record<string, unknown> = {};
  for (const key of allowList) {
    if (Object.prototype.hasOwnProperty.call(args, key)) {
      scrubbed[key] = args[key];
    }
  }
  return scrubbed;
}

/**
 * Gzip-compresses a UTF-8 string using the native CompressionStream API.
 * Returns a `Uint8Array` of the compressed bytes.
 *
 * Available in Node.js ≥ 18 and Cloudflare Workers. Falls back to identity
 * (no compression) in environments where CompressionStream is unavailable.
 */
async function gzip(text: string): Promise<Uint8Array> {
  if (typeof CompressionStream === "undefined") {
    // Graceful degradation: return raw UTF-8 bytes without compression.
    return new TextEncoder().encode(text);
  }
  const encoder = new TextEncoder();
  const inputStream = new ReadableStream<Uint8Array>({
    start(controller) {
      controller.enqueue(encoder.encode(text));
      controller.close();
    },
  });
  // Cast through unknown to bypass the strict Uint8Array<ArrayBuffer> vs
  // Uint8Array<ArrayBufferLike> mismatch in the CompressionStream type definitions.
  const compressedStream = inputStream.pipeThrough(
    new CompressionStream("gzip") as unknown as TransformStream<Uint8Array, Uint8Array>,
  );
  const reader = compressedStream.getReader();
  const chunks: Uint8Array[] = [];
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
  }
  const totalLength = chunks.reduce((acc, c) => acc + c.length, 0);
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const chunk of chunks) {
    result.set(chunk, offset);
    offset += chunk.length;
  }
  return result;
}

// ---------------------------------------------------------------------------
// VCR Replay Cache
// ---------------------------------------------------------------------------

/**
 * In-memory VCR replay store, populated during `volidator replay` CLI hydration.
 * Keyed by SHA-256(toolName + JSON.stringify(args)).
 *
 * The SDK checks this store when VOLIDATOR_REPLAY_MODE is set, returning the
 * cached output instead of executing the real tool function.
 */
const _replayStore = new Map<string, unknown>();

/**
 * Loads a pre-hydrated VCR replay map into the in-memory store.
 * Called by the `volidator replay` CLI after decrypting and decompressing
 * the R2 evidence bundle.
 *
 * @param vcr - Map of SHA-256(toolName + args) → historical tool output.
 */
export function loadReplayStore(vcr: Map<string, unknown>): void {
  _replayStore.clear();
  for (const [k, v] of vcr.entries()) {
    _replayStore.set(k, v);
  }
}

/**
 * Returns true when the SDK is operating in VCR replay mode.
 * Detected via the `VOLIDATOR_REPLAY_MODE` environment variable.
 */
function isReplayMode(): boolean {
  if (typeof process !== "undefined") {
    return process.env.VOLIDATOR_REPLAY_MODE === "1";
  }
  return false;
}

// ---------------------------------------------------------------------------
// Core: wrapToolForVCR
// ---------------------------------------------------------------------------

/**
 * Wraps a tool's execute function with FDR evidence capture.
 *
 * In normal (production) mode:
 *   1. Executes the real tool function.
 *   2. Captures scrubbed input args, raw output, and latency.
 *   3. Appends the record to the provided `FdrRunContext`.
 *
 * In replay mode (`VOLIDATOR_REPLAY_MODE=1`):
 *   1. Computes the VCR lookup key from the tool name and scrubbed args.
 *   2. Returns the historical output from the in-memory replay store.
 *   3. Does NOT execute the real tool function (agent is air-gapped).
 *
 * @param toolName   Stable identifier for the tool (e.g. "fetch_stock_price").
 * @param executeFn  The original async tool implementation.
 * @param runCtx     The FdrRunContext accumulator for this agent run.
 * @param options    Optional VCR configuration (allow-list, etc.).
 */
export function wrapToolForVCR<TArgs extends Record<string, unknown>, TOutput>(
  toolName: string,
  executeFn: (args: TArgs) => Promise<TOutput>,
  runCtx: FdrRunContext,
  options?: VcrWrapOptions,
): (args: TArgs) => Promise<TOutput> {
  return async (args: TArgs): Promise<TOutput> => {
    const scrubbedArgs = scrubArgs(args as Record<string, unknown>, options?.allowList);
    const argsJson = JSON.stringify(scrubbedArgs);
    const argsHash = await sha256hex(toolName + argsJson);

    // --- Replay Mode: return cached historical output ---
    if (isReplayMode()) {
      const cached = _replayStore.get(argsHash);
      if (cached === undefined) {
        throw new Error(
          `[Volidator FDR Replay] No cached output found for tool "${toolName}" with args hash "${argsHash}". ` +
            `Ensure the run was captured with the same allow-list configuration.`,
        );
      }
      return cached as TOutput;
    }

    // --- Production Mode: execute real tool and capture evidence ---
    const capturedAt = Date.now();
    const output = await executeFn(args);
    const latencyMs = Date.now() - capturedAt;

    const record: FdrToolRecord = {
      seq: ++runCtx._seq,
      toolName,
      argsHash,
      args: scrubbedArgs,
      output,
      latencyMs,
      capturedAt,
    };

    runCtx.tools.push(record);
    return output;
  };
}

// ---------------------------------------------------------------------------
// Evidence Bundle Construction
// ---------------------------------------------------------------------------

/**
 * Finalises and serialises the FDR evidence bundle for a completed agent run.
 * Returns a gzip-compressed `Uint8Array` ready for upload to R2.
 *
 * @param runCtx  The accumulated FdrRunContext from the completed run.
 */
export async function buildEvidenceBundle(runCtx: FdrRunContext): Promise<Uint8Array> {
  const bundle: FdrEvidenceBundle = {
    version: 1,
    runId: runCtx.runId,
    projectId: runCtx.projectId,
    systemPromptHash: runCtx.systemPromptHash,
    systemPrompt: runCtx.systemPrompt,
    providerAlibi: runCtx.providerAlibi,
    tools: runCtx.tools,
    committedAt: Date.now(),
  };
  return gzip(JSON.stringify(bundle));
}

/**
 * Computes a SHA-256 hash of the system prompt text and stores both the hash
 * and the plaintext in the run context. The plaintext is included in the
 * encrypted R2 evidence bundle; the hash is committed to the D1 ledger row
 * as a quick integrity reference.
 */
export async function captureSystemPrompt(runCtx: FdrRunContext, prompt: string): Promise<void> {
  runCtx.systemPrompt = prompt;
  runCtx.systemPromptHash = await sha256hex(prompt);
}

/**
 * Attaches provider alibi metadata (model version, system_fingerprint, seed)
 * to the run context. Should be called after the LLM response is received.
 */
export function captureProviderAlibi(runCtx: FdrRunContext, alibi: FdrProviderAlibi): void {
  runCtx.providerAlibi = alibi;
}

/**
 * Creates a fresh, empty FdrRunContext for a new agent run.
 */
export function createFdrRunContext(runId: string, projectId: string): FdrRunContext {
  return {
    runId,
    projectId,
    tools: [],
    _seq: 0,
  };
}

/**
 * Computes the SHA-256 hex digest of the raw bytes of a gzipped evidence bundle.
 * This hash is committed to the D1 fdr_ledger as the payload_hash, used for
 * chain integrity verification.
 */
export async function hashEvidenceBundle(gzippedBytes: Uint8Array): Promise<string> {
  const hashBuf = await globalThis.crypto.subtle.digest("SHA-256", gzippedBytes.buffer as ArrayBuffer);
  return Array.from(new Uint8Array(hashBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}
