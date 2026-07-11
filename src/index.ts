import { AsyncLocalStorage } from "node:async_hooks";

// ---------------------------------------------------------------------------
// Reference-Based Redaction Types
// ---------------------------------------------------------------------------

/**
 * A structured payload for fields listed in `referenceKeys`.
 * - `id`  — the non-sensitive internal identifier stored in Volidator as [REF:id].
 * - `pii` — the real value used ONLY to compute the blind index, then discarded.
 *
 * @example
 *   actor: { id: "usr_890", pii: "john@company.com" }
 *   // stored:      "[REF:usr_890]"
 *   // blind index: HMAC("john@company.com")
 *   // telemetry:  extracted automatically or passed in context
 */
export type ReferencePayload = { id: string; pii: string };

/**
 * Utility type that enforces { id, pii } shape on any LogPayload fields
 * whose key appears in the `referenceKeys` constructor option.
 * Gives a compile-time error if a developer passes a raw string instead.
 */
export type EnforceReference<TData, TRefKeys extends keyof TData> = Omit<TData, TRefKeys> & {
  [K in TRefKeys]: ReferencePayload;
};

export interface TelemetryConfig {
  preset?: "strict" | "standard" | "full";
  ip?: "track" | "anonymize" | "skip";
  userAgent?: "track" | "parse" | "skip";
  location?: boolean;
}

export interface BatcherOptions {
  /**
   * Automatically flush and send logs when the buffer reaches this count.
   * Maximum count is capped at 100.
   */
  autoFlushCount?: number;
  /**
   * Automatically flush and send logs every N milliseconds.
   *
   * ⚠️ SERVERLESS/EDGE CAVEAT:
   * Do not use in serverless/edge environments (e.g. Cloudflare Workers, Vercel Edge)
   * as background timers are not guaranteed to execute after response completion.
   */
  autoFlushInterval?: number;
}

export interface VolidatorBatcher {
  /**
   * Push a log payload to the buffer. Auto-flushes if autoFlushCount limit is reached.
   */
  push(payload: LogPayload): void;
  /**
   * Manually flush the buffer and send all logs.
   */
  flush(): Promise<{ accepted: number; rejected: number }>;
  /**
   * Returns the current size of the buffer.
   */
  size(): number;
}

export interface TelemetryContext {
  ip?: string;
  userAgent?: string;
  location?: {
    country?: string;
    region?: string;
    city?: string;
  };
  device?: {
    browser?: string;
    os?: string;
    type?: string;
  };
  [key: string]: any;
}

export interface LogPayload {
  /**
   * The actor performing the action. Pass a plain string for normal logs.
   * Pass a `ReferencePayload` when this field is listed in `referenceKeys`:
   *   actor: { id: "usr_890", pii: "john@company.com" }
   */
  actor?: string | ReferencePayload;
  actorId?: string; // support actorId as alias (plain string only)
  action: string;
  /**
   * The target of the action. Pass a plain string for normal logs.
   * Pass a `ReferencePayload` when this field is listed in `referenceKeys`.
   */
  target?: string | ReferencePayload;
  targetId?: string; // support targetId as alias (plain string only)
  /**
   * The tenant or client identifier (e.g. B2B company name/ID).
   * Pass a plain string for normal logs, or a `ReferencePayload`.
   */
  tenant?: string | ReferencePayload;
  tenantId?: string; // support tenantId as alias (plain string only)
  /**
   * Groups all events belonging to a single agent run, workflow execution,
   * or request trace. Passed through as a blind index so the server can
   * filter by run without decrypting payloads.
   */
  traceId?: string;
  /**
   * Identifies this specific event within the trace (analogous to OTel spanId).
   */
  spanId?: string;
  /**
   * The spanId of the event that caused this one (parentSpanId).
   */
  parentSpanId?: string;
  /**
   * Arbitrary metadata. Values for keys listed in `referenceKeys` must be
   * `ReferencePayload` objects: { id: "ref_id", pii: "sensitive_value" }.
   */
  metadata?: Record<string, any>;
  context?: TelemetryContext;
  telemetry?: TelemetryConfig;
  req?: Request | import("node:http").IncomingMessage; // support passing the HTTP request object directly
  /**
   * Sequence number/counter to mathematically trace causal event chains
   */
  logicalClock?: number;
  /**
   * If true, indicates the log payload is stored externally in R2
   */
  isClaimCheck?: boolean;
  /**
   * Optional thought pattern/rationale behind this action. Truncated to 1000 characters and E2EE.
   */
  rationale?: string;
  /**
   * Optional tool name associated with this agent action. E2EE.
   */
  toolName?: string;
  /**
   * Optional WebAuthn attestation signature package for high-risk action verification.
   */
  attestation?: {
    challenge: string;
    signature: string;
    authenticatorData: string;
    credentialId: string;
  };
}

interface EmbedTokenViewConfig {
  /** The columns to show in the table, e.g. ["actor", "action", "metadata.region", "createdAt"] */
  columns?: string[];
  /** Default search filters loaded on mount */
  defaultFilter?: {
    search?: string;
    action?: string;
  };
}

interface EmbedTokenConfig {
  /** The plaintext actor identifier (e.g. "usr_123") */
  actorId?: string;
  /** The plaintext target identifier (e.g. "usr_123") */
  targetId?: string;
  /** The plaintext tenant identifier (e.g. "johnsbakery") */
  tenantId?: string;
  /** Scopes the logs to query. If not provided, defaults to 'actor' if actorId is provided, or 'tenant' if tenantId is provided. */
  scope?: "actor" | "target" | "tenant" | "all" | "auditor";
  /** Duration string: "30m", "2h", "7d". Defaults to "2h". */
  expiresIn?: string;
  /** Custom dashboard origin URL override */
  dashboardUrl?: string;
  /** Optional origin of host app for iframe postMessage domain validation */
  hostOrigin?: string;
  /** Custom column presentation and default filters */
  view?: EmbedTokenViewConfig;
}

interface EmbedTokenResult {
  token: string;
  embedUrl: string;
}

export class VolidatorClient {
  private apiKey: string;
  private endpoint: string;
  private telemetryConfig: Required<Omit<TelemetryConfig, "preset">>;

  // Optional fields required only for generateEmbedToken()
  private projectId?: string;
  private clientSecret?: string;

  private redactKeys: string[];
  private referenceKeys: string[];

  // Keyring properties
  private activeKeyId: string;
  private keyring: Record<string, string>;
  private hashedKeyring: Record<string, Uint8Array>;

  // Custom limit for metadata object serialization size
  private maxMetadataSize: number;

  private maxRetries: number;
  private onDeliveryFailure?: (payload: LogPayload, error: Error) => void;

  /**
   * Thread-local asynchronous context storage used to maintain
   * and increment Lamport logical clock sequences across execution boundaries
   * (e.g. within API requests or serverless handler contexts).
   */
  /**
   * Optional registered callback to extract trace details dynamically from
   * OpenTelemetry context if active. Avoids dynamic imports or OTel library
   * checks in high-frequency execution paths.
   */
  public static otelContextResolver: (() => { traceId?: string; spanId?: string } | null) | null = null;

  public static readonly logicalClockStore: AsyncLocalStorage<{ clock: number }> =
    new AsyncLocalStorage<{ clock: number }>();
  private fallbackLogicalClock = 0;

  /**
   * Thread-local asynchronous context storage used to propagate and automatically
   * attach trace, span, rationale, and tool context to log events and HTTP headers.
   */
  public static readonly agentContextStore: AsyncLocalStorage<{
    traceId?: string;
    spanId?: string;
    rationale?: string;
    toolName?: string;
  }> = new AsyncLocalStorage();

  /**
   * Run an asynchronous execution chain within an active AI Agent context.
   * Any HTTP client calls or log events executed within this block will automatically
   * inherit and propagate these headers.
   */
  public runInAgentContext<T>(
    context: { traceId?: string; spanId?: string; rationale?: string; toolName?: string },
    fn: () => Promise<T>,
  ): Promise<T> {
    return VolidatorClient.agentContextStore.run(context, fn);
  }

  /**
   * Increments and returns the current Lamport Logical Clock counter.
   * If a logicalClockStore context is active, it reads, syncs, and updates
   * the thread-scoped clock; otherwise, it falls back to a global instance-scoped counter.
   *
   * @param incomingClock Optional logical clock sequence from incoming trace parent header
   */
  public getAndIncrementClock(incomingClock?: number): number {
    const store = VolidatorClient.logicalClockStore.getStore();
    if (store) {
      store.clock = Math.max(store.clock, incomingClock || 0) + 1;
      return store.clock;
    }
    this.fallbackLogicalClock = Math.max(this.fallbackLogicalClock, incomingClock || 0) + 1;
    return this.fallbackLogicalClock;
  }

  public compliance: VolidatorCompliance;
  public agent: VolidatorAgent;

  constructor(config: {
    apiKey: string;
    encryptionKey?: string;
    activeEncryptionKeyId?: string;
    keyring?: Record<string, string>;
    endpoint?: string;
    // Provide these when you need to generate embed tokens server-side
    projectId?: string;
    clientSecret?: string;
    telemetry?: TelemetryConfig;
    /**
     * Fields to replace with [REDACTED:key] before encryption.
     */
    redactKeys?: string[];
    /**
     * Fields to replace with [REF:id] before encryption (JIT Hydration).
     */
    referenceKeys?: string[];
    /**
     * Custom maximum size for serialized metadata in bytes. Defaults to 10240 (10KB).
     * Serialized metadata is subject to a depth limit of 5 levels and values are
     * truncated to 1000 characters.
     */
    maxMetadataSize?: number;
    /**
     * Maximum number of delivery retry attempts for transient errors. Defaults to 3.
     */
    maxRetries?: number;
    /**
     * Callback fired when an event terminals fails to deliver after all retries.
     */
    onDeliveryFailure?: (payload: LogPayload, error: Error) => void;
  }) {
    this.apiKey = config.apiKey;
    this.endpoint = config.endpoint || "https://ingestion.volidator.com";
    this.projectId = config.projectId;
    this.clientSecret = config.clientSecret;
    this.redactKeys = config.redactKeys || [];
    this.referenceKeys = config.referenceKeys || [];
    this.maxMetadataSize = config.maxMetadataSize || 10240;
    this.maxRetries = config.maxRetries !== undefined ? config.maxRetries : 3;
    this.onDeliveryFailure = config.onDeliveryFailure;

    // Parse encryption keys & keyring
    if (config.keyring && config.activeEncryptionKeyId) {
      this.keyring = config.keyring;
      this.activeKeyId = config.activeEncryptionKeyId;
    } else if (config.encryptionKey) {
      this.activeKeyId = "v1";
      this.keyring = { v1: config.encryptionKey };
    } else {
      throw new Error(
        "Either encryptionKey OR (keyring AND activeEncryptionKeyId) must be provided in VolidatorClient constructor.",
      );
    }

    // Limit keyring size to 5 for performance & security
    if (Object.keys(this.keyring).length > 5) {
      throw new Error("Keyring size cannot exceed 5 keys.");
    }

    if (!this.keyring[this.activeKeyId]) {
      throw new Error(`Active key ID '${this.activeKeyId}' must exist in the keyring.`);
    }

    // Keys will be hashed lazily via WebCrypto in _getHashedKey
    this.hashedKeyring = {};

    // Default to 'standard' preset if nothing is provided
    this.telemetryConfig = VolidatorClient.resolveTelemetryConfig(
      config.telemetry || { preset: "standard" },
    );
    this.compliance = new VolidatorCompliance(this);
    this.agent = new VolidatorAgent(this);
  }

  // ---------------------------------------------------------------------------
  // Telemetry Context Parser (Zero-latency header parsing)
  // ---------------------------------------------------------------------------
  static extractContext(req: any): TelemetryContext {
    const getHeader = (name: string): string => {
      if (!req) return "";
      // Handle standard Web API Request/Headers
      if (typeof req.headers?.get === "function") {
        return req.headers.get(name) || "";
      }
      // Handle Node.js IncomingMessage request headers
      if (req.headers && typeof req.headers === "object") {
        return req.headers[name] || req.headers[name.toLowerCase()] || "";
      }
      return "";
    };

    const rawIp =
      getHeader("cf-connecting-ip") || getHeader("x-real-ip") || getHeader("x-forwarded-for");

    const ip = rawIp ? rawIp.split(",")[0].trim() : req?.socket?.remoteAddress || "";
    const userAgent = getHeader("user-agent");

    return {
      ip,
      userAgent,
      location: {
        country: getHeader("cf-ipcountry") || getHeader("x-vercel-ip-country") || "",
        region: getHeader("cf-region-code") || getHeader("x-vercel-ip-country-region") || "",
        city: getHeader("cf-ipcity") || getHeader("x-vercel-ip-city") || "",
      },
    };
  }

  // ---------------------------------------------------------------------------
  // OpenTelemetry W3C traceparent context parser
  // ---------------------------------------------------------------------------
  static extractTraceContext(req: any): {
    traceId?: string;
    spanId?: string;
    logicalClock?: number;
  } {
    if (!req) return {};
    const getHeader = (name: string): string => {
      if (typeof req.headers?.get === "function") {
        return req.headers.get(name) || "";
      }
      if (req.headers && typeof req.headers === "object") {
        return req.headers[name] || req.headers[name.toLowerCase()] || "";
      }
      return "";
    };

    const result: { traceId?: string; spanId?: string; logicalClock?: number } = {};

    const clockVal = getHeader("x-volidator-clock");
    if (clockVal) {
      const parsed = parseInt(clockVal, 10);
      if (!isNaN(parsed)) {
        result.logicalClock = parsed;
      }
    }

    const traceparent = getHeader("traceparent");
    if (traceparent) {
      const parts = traceparent.split("-");
      if (parts.length === 4) {
        result.traceId = parts[1];
        result.spanId = parts[2];
      }
    }
    return result;
  }

  private static resolveTelemetryConfig(
    config: TelemetryConfig,
  ): Required<Omit<TelemetryConfig, "preset">> {
    const preset = config.preset || "standard";

    let ip: "track" | "anonymize" | "skip" = "anonymize";
    let userAgent: "track" | "parse" | "skip" = "parse";
    let location = true;

    if (preset === "strict") {
      ip = "skip";
      userAgent = "skip";
      location = false;
    } else if (preset === "full") {
      ip = "track";
      userAgent = "track";
      location = true;
    }

    if (config.ip !== undefined) ip = config.ip;
    if (config.userAgent !== undefined) userAgent = config.userAgent;
    if (config.location !== undefined) location = config.location;

    return { ip, userAgent, location };
  }

  private parseUserAgent(ua: string) {
    let browser = "Unknown Browser";
    let os = "Unknown OS";
    let type = "Desktop";

    if (/Volidator-Ingest-Worker/i.test(ua)) {
      return {
        browser: "Volidator Ingest Worker",
        os: "Linux Server",
        type: "Server",
      };
    }

    // Simple Device Type detection
    if (/mobile/i.test(ua)) {
      type = "Mobile";
    } else if (/tablet|ipad/i.test(ua)) {
      type = "Tablet";
    } else if (/server|bot/i.test(ua)) {
      type = "Server";
    }

    // Simple Browser detection
    if (/chrome|crios/i.test(ua) && !/edge|edg/i.test(ua) && !/opr/i.test(ua)) {
      const match = ua.match(/(?:chrome|crios)\/([0-9.]+)/i);
      browser = `Chrome ${match ? match[1].split(".")[0] : ""}`.trim();
    } else if (/safari/i.test(ua) && !/chrome|crios/i.test(ua) && !/android/i.test(ua)) {
      browser = /mobile/i.test(ua) ? "Safari Mobile" : "Safari";
    } else if (/firefox|fxios/i.test(ua)) {
      browser = "Firefox";
    } else if (/edge|edg/i.test(ua)) {
      browser = "Edge";
    }

    // Simple OS detection
    if (/windows/i.test(ua)) {
      os = "Windows";
    } else if (/macintosh|mac os x/i.test(ua)) {
      os = "macOS";
    } else if (/iphone|ipad|ipod/i.test(ua)) {
      os = "iOS";
    } else if (/android/i.test(ua)) {
      os = "Android";
    } else if (/linux/i.test(ua)) {
      os = "Linux";
    }

    return { browser, os, type };
  }

  // ---------------------------------------------------------------------------
  // Blind Index & Key Hashing (WebCrypto)
  // ---------------------------------------------------------------------------
  private async _getHashedKey(id: string): Promise<Uint8Array> {
    if (this.hashedKeyring[id]) return this.hashedKeyring[id];
    const rawKey = this.keyring[id];
    const buf = new TextEncoder().encode(rawKey);
    const hash = await globalThis.crypto.subtle.digest("SHA-256", buf);
    this.hashedKeyring[id] = new Uint8Array(hash);
    return this.hashedKeyring[id];
  }

  private async generateBlindIndex(value: string, keyBuffer: Uint8Array): Promise<string> {
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      keyBuffer as unknown as BufferSource,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signature = await globalThis.crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(value),
    );
    return Array.from(new Uint8Array(signature))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  // ---------------------------------------------------------------------------
  // Payload Encryption — AES-256-GCM with prepended 12-byte IV
  // Layout: [IV (12B)] [Ciphertext] [Auth Tag (16B)]
  // ---------------------------------------------------------------------------
  private async encryptPayload(payload: object): Promise<string> {
    const text = JSON.stringify(payload);
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const activeHashedKey = await this._getHashedKey(this.activeKeyId);

    const cryptoKey = await globalThis.crypto.subtle.importKey(
      "raw",
      activeHashedKey as unknown as BufferSource,
      { name: "AES-GCM" },
      false,
      ["encrypt"],
    );

    const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv },
      cryptoKey,
      new TextEncoder().encode(text),
    );

    const finalBuffer = new Uint8Array(iv.length + encryptedBuffer.byteLength);
    finalBuffer.set(iv, 0);
    finalBuffer.set(new Uint8Array(encryptedBuffer), iv.length);

    // Convert to base64 safely for edges
    let binary = "";
    const len = finalBuffer.byteLength;
    for (let i = 0; i < len; i++) {
      binary += String.fromCharCode(finalBuffer[i]);
    }
    const base64 = btoa(binary);
    return `${this.activeKeyId}:${base64}`;
  }

  // ---------------------------------------------------------------------------
  // prepareLogEntry() — Prepares, redacts, and encrypts a single log entry payload
  // ---------------------------------------------------------------------------
  private async prepareLogEntry(payload: LogPayload, maxMetaOverride?: number) {
    // Resolve trace context synchronously at the very start to avoid losing context during async execution yields
    let traceId = payload.traceId;
    let spanId = payload.spanId;

    if (!traceId || !spanId) {
      if (VolidatorClient.otelContextResolver) {
        try {
          const otelCtx = VolidatorClient.otelContextResolver();
          if (otelCtx) {
            if (!traceId && otelCtx.traceId) {
              traceId = otelCtx.traceId;
            }
            if (!spanId && otelCtx.spanId) {
              spanId = otelCtx.spanId;
            }
          }
        } catch {}
      }
    }

    // Hard ceiling guardrail: reject immediately if raw metadata exceeds 5MB limit
    const PAYLOAD_5MB_LIMIT = 5 * 1024 * 1024;
    const metadata = payload.metadata || {};
    const payloadSize = new TextEncoder().encode(JSON.stringify(metadata)).length;

    if (payloadSize > PAYLOAD_5MB_LIMIT) {
      throw new Error(
        `Volidator SDK Error: Audit log payload exceeds the 5MB hard limit (${payloadSize} bytes).`,
      );
    }

    const actorRaw = payload.actor || payload.actorId || "unknown";
    const targetRaw = payload.target || payload.targetId || "unknown";
    const tenantRaw = payload.tenant || payload.tenantId || "";

    const truncate = (str: string, maxLen: number): string => {
      if (str.length > maxLen) {
        return str.slice(0, maxLen) + "...";
      }
      return str;
    };

    const extractPii = (v: string | ReferencePayload): string =>
      typeof v === "object" ? v.pii : v;
    const extractId = (v: string | ReferencePayload): string => (typeof v === "object" ? v.id : v);

    const actor = truncate(extractPii(actorRaw), 255);
    const target = truncate(extractPii(targetRaw), 255);
    const tenant = tenantRaw ? truncate(extractPii(tenantRaw), 255) : "";
    const action = truncate(payload.action, 255);

    const logTelemetry = payload.telemetry
      ? VolidatorClient.resolveTelemetryConfig({ ...this.telemetryConfig, ...payload.telemetry })
      : this.telemetryConfig;

    let payloadCtx = payload.context || {};
    if (payload.req) {
      const extracted = VolidatorClient.extractContext(payload.req);
      payloadCtx = {
        ...extracted,
        ...payloadCtx,
        location: {
          ...extracted.location,
          ...payloadCtx.location,
        },
        device: {
          ...extracted.device,
          ...payloadCtx.device,
        },
      };
    }

    const context: TelemetryContext = {};
    const rawIp = payloadCtx.ip || "";
    const rawUa = payloadCtx.userAgent || "";

    if (logTelemetry.location) {
      context.location = {};
      if (payloadCtx.location) {
        context.location.country = payloadCtx.location.country || "";
        context.location.region = payloadCtx.location.region || "";
        const isFull =
          payload.telemetry?.preset === "full" ||
          (!payload.telemetry && this.telemetryConfig.ip === "track");
        if (logTelemetry.ip === "track" || isFull) {
          context.location.city = payloadCtx.location.city || "";
        }
      }
    }

    if (logTelemetry.ip === "anonymize" && rawIp) {
      context.ip = await this.generateBlindIndex(rawIp, await this._getHashedKey(this.activeKeyId));
    } else if (logTelemetry.ip === "track" && rawIp) {
      context.ip = rawIp;
    }

    if (logTelemetry.userAgent !== "skip") {
      if (rawUa) {
        context.device = this.parseUserAgent(rawUa);
        if (logTelemetry.userAgent === "track") {
          context.userAgent = truncate(rawUa, 1000);
        }
      } else if (payloadCtx.device) {
        context.device = payloadCtx.device;
      }
    }

    const scrub = (value: string, key: string): string =>
      this.redactKeys.includes(key) ? `[REDACTED:${key}]` : value;

    const applyRef = (rawValue: string | ReferencePayload, key: string): string => {
      if (this.referenceKeys.includes(key)) {
        const id = extractId(rawValue);
        return `[REF:${id}]`;
      }
      return scrub(extractPii(rawValue), key);
    };

    const rawMetadata = payload.metadata || {};
    const safeMetadata: Record<string, any> = {};
    for (const [k, v] of Object.entries(rawMetadata)) {
      const metaKey = `metadata.${k}`;
      if (
        this.referenceKeys.includes(metaKey) &&
        typeof v === "object" &&
        v !== null &&
        "id" in v
      ) {
        safeMetadata[k] = `[REF:${(v as ReferencePayload).id}]`;
      } else if (this.redactKeys.includes(metaKey) && typeof v === "string") {
        safeMetadata[k] = `[REDACTED:${k}]`;
      } else {
        safeMetadata[k] = v;
      }
    }

    let didTruncateDepth = false;
    let didTruncateString = false;

    const limitDepth = (obj: any, currentDepth = 1): any => {
      if (currentDepth > 5) {
        didTruncateDepth = true;
        return "[Truncated - Depth Exceeded]";
      }
      if (typeof obj !== "object" || obj === null) {
        if (typeof obj === "string") {
          const truncatedVal = truncate(obj, 1000);
          if (truncatedVal.length !== obj.length) {
            didTruncateString = true;
          }
          return truncatedVal;
        }
        return obj;
      }
      if (Array.isArray(obj)) {
        return obj.map((item) => limitDepth(item, currentDepth + 1));
      }
      const result: Record<string, any> = {};
      for (const [key, val] of Object.entries(obj)) {
        result[key] = limitDepth(val, currentDepth + 1);
      }
      return result;
    };

    const processedMetadata = limitDepth(safeMetadata);

    if (typeof process !== "undefined" && process.env?.NODE_ENV !== "production") {
      if (didTruncateDepth) {
        console.warn(
          "[Volidator] Warning: Log metadata exceeded maximum depth limit (5) and was truncated.",
        );
      }
      if (didTruncateString) {
        console.warn(
          "[Volidator] Warning: One or more log metadata string values exceeded the 1000-character limit and were truncated.",
        );
      }
    }

    const serializedMeta = JSON.stringify(processedMetadata);
    const maxMetaLimit = maxMetaOverride || this.maxMetadataSize;
    if (serializedMeta.length > maxMetaLimit) {
      throw new Error(`Metadata size exceeds maximum allowed limit of ${maxMetaLimit / 1024}KB.`);
    }

    const safeActor = applyRef(actorRaw, "actor");
    const safeTarget = applyRef(targetRaw, "target");
    const safeTenant = tenantRaw ? applyRef(tenantRaw, "tenant") : undefined;

    const enrichedPayload: any = {
      actor: safeActor,
      action,
      target: safeTarget,
      metadata: processedMetadata,
    };

    if (safeTenant) {
      enrichedPayload.tenant = safeTenant;
    }

    if (Object.keys(context).length > 0) {
      enrichedPayload.context = context;
    }

    // Auto-extract trace contexts and logical clock from incoming request if present
    const parentSpanId = payload.parentSpanId;
    let logicalClock = payload.logicalClock;

    // Check thread-local async context store for agent credentials/trace
    const agentCtx = VolidatorClient.agentContextStore.getStore();
    if (agentCtx) {
      if (!traceId && agentCtx.traceId) {
        traceId = agentCtx.traceId;
      }
      if (!spanId && agentCtx.spanId) {
        spanId = agentCtx.spanId;
      }
    }

    if (payload.req) {
      const extractedTrace = VolidatorClient.extractTraceContext(payload.req);
      if (!traceId && extractedTrace.traceId) {
        traceId = extractedTrace.traceId;
      }
      if (!spanId && extractedTrace.spanId) {
        spanId = extractedTrace.spanId;
      }
      if (logicalClock === undefined && extractedTrace.logicalClock !== undefined) {
        logicalClock = extractedTrace.logicalClock;
      }
    }

    const resolvedClock = this.getAndIncrementClock(logicalClock);

    if (spanId) {
      enrichedPayload.spanId = spanId;
    }
    if (parentSpanId) {
      enrichedPayload.parentSpanId = parentSpanId;
    }

    const activeKeyBuffer = await this._getHashedKey(this.activeKeyId);
    const actorBlindIndex = await this.generateBlindIndex(actor, activeKeyBuffer);
    const actionBlindIndex = await this.generateBlindIndex(action, activeKeyBuffer);
    const targetBlindIndex = await this.generateBlindIndex(target, activeKeyBuffer);
    const tenantBlindIndex = tenant
      ? await this.generateBlindIndex(tenant, activeKeyBuffer)
      : undefined;
    const traceBlindIndex = traceId
      ? await this.generateBlindIndex(traceId, activeKeyBuffer)
      : undefined;

    let encryptedPayload = await this.encryptPayload(enrichedPayload);
    let isClaimCheck = false;

    if (encryptedPayload.length > 30720) {
      // Calculate content hash of the encrypted payload
      const binaryBuffer = new TextEncoder().encode(encryptedPayload);
      const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", binaryBuffer);
      const hashHex = Array.from(new Uint8Array(hashBuffer))
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      // Upload encrypted payload to edge worker storage endpoint
      try {
        const uploadRes = await fetch(`${this.endpoint}/v1/log/upload/${hashHex}`, {
          method: "PUT",
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            "Content-Type": "application/octet-stream",
          },
          body: encryptedPayload,
        });
        if (!uploadRes.ok) {
          throw new Error(`Upload failed with status: ${uploadRes.status}`);
        }
        // Change payload to contain only the hash
        encryptedPayload = hashHex;
        isClaimCheck = true;
      } catch (err: any) {
        console.error(`[Volidator] Claim check upload failed: ${err.message}`);
        // Fall back to original payload and let the worker enforce limits if upload fails
      }
    }

    const rationale = payload.rationale || agentCtx?.rationale;
    const toolName = payload.toolName || agentCtx?.toolName;

    let agentContext: string | null = null;
    if (rationale || toolName) {
      const truncatedRationale = rationale ? rationale.slice(0, 1000) : undefined;
      agentContext = await this.encryptPayload({
        rationale: truncatedRationale,
        toolName: toolName,
      });
    }

    const attestationProof = payload.attestation ? JSON.stringify(payload.attestation) : null;

    return {
      actorBlindIndex,
      actionBlindIndex,
      targetBlindIndex,
      tenantBlindIndex,
      traceBlindIndex,
      encryptedPayload,
      logicalClock: resolvedClock,
      isClaimCheck,
      agentContext,
      attestationProof,
    };
  }

  // ---------------------------------------------------------------------------
  // fetchWithRetry() — Private helper to perform robust HTTP requests with backoff
  // ---------------------------------------------------------------------------
  private async fetchWithRetry(
    url: string,
    options: RequestInit,
    maxRetries = this.maxRetries,
  ): Promise<Response> {
    let attempt = 0;
    let delay = 500;
    let lastError: Error = new Error("Unknown error");

    while (attempt <= maxRetries) {
      try {
        const res = await fetch(url, options);

        if (res.ok) {
          return res;
        }

        lastError = new Error(`Server returned status ${res.status}`);

        // Do not retry 4xx client errors (bad request, unauthorized, forbidden, etc.)
        if (res.status >= 400 && res.status < 500) {
          break;
        }
      } catch (err: unknown) {
        lastError = err instanceof Error ? err : new Error(String(err));
      }

      attempt++;
      if (attempt <= maxRetries) {
        await new Promise<void>((resolve) => setTimeout(resolve, delay));
        delay *= 3;
      }
    }

    throw lastError;
  }

  // ---------------------------------------------------------------------------
  // log() — Encrypt and ingest a single audit event
  // ---------------------------------------------------------------------------
  async log(payload: LogPayload, maxMetaOverride?: number): Promise<boolean> {
    const entry = await this.prepareLogEntry(payload, maxMetaOverride);

    try {
      const res = await this.fetchWithRetry(`${this.endpoint}/v1/log`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(entry),
      });

      if (res.ok) {
        return true;
      }
    } catch (err: unknown) {
      const errorObj = err instanceof Error ? err : new Error(String(err));
      console.error(`[Volidator] Failed to send log: ${errorObj.message}`);
      if (this.onDeliveryFailure) {
        try {
          this.onDeliveryFailure(payload, errorObj);
        } catch (cbErr: unknown) {
          const cbErrorObj = cbErr instanceof Error ? cbErr : new Error(String(cbErr));
          console.error(`[Volidator] Error in onDeliveryFailure callback: ${cbErrorObj.message}`);
        }
      }
    }
    return false;
  }

  // ---------------------------------------------------------------------------
  // logBatch() — Bulk encrypt and ingest a batch of up to 100 audit events
  // ---------------------------------------------------------------------------
  async logBatch(
    payloads: LogPayload[],
    maxMetaOverride?: number,
  ): Promise<{ accepted: number; rejected: number }> {
    if (!Array.isArray(payloads) || payloads.length === 0) {
      return { accepted: 0, rejected: 0 };
    }

    // Cap batch size at 100
    const batch = payloads.slice(0, 100);
    const preparedEntries: Record<string, unknown>[] = [];
    let rejected = payloads.length - batch.length;

    const results = await Promise.allSettled(
      batch.map((p) => this.prepareLogEntry(p, maxMetaOverride)),
    );

    for (const res of results) {
      if (res.status === "fulfilled") {
        preparedEntries.push(res.value);
      } else {
        rejected++;
        console.error(`[Volidator] Failed to prepare batch entry: ${res.reason?.message}`);
      }
    }

    if (preparedEntries.length === 0) {
      return { accepted: 0, rejected };
    }

    try {
      const res = await this.fetchWithRetry(`${this.endpoint}/v1/logs/batch`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ logs: preparedEntries }),
      });

      if (res.ok) {
        return { accepted: preparedEntries.length, rejected };
      } else {
        console.error(`[Volidator] Batch ingestion endpoint returned status: ${res.status}`);
        return { accepted: 0, rejected: rejected + preparedEntries.length };
      }
    } catch (err: unknown) {
      const errorObj = err instanceof Error ? err : new Error(String(err));
      console.error(`[Volidator] Failed to send log batch after retries: ${errorObj.message}`);
      if (this.onDeliveryFailure) {
        try {
          // Notify callback of each payload that failed delivery in this batch
          for (const payload of batch) {
            this.onDeliveryFailure(payload, errorObj);
          }
        } catch (cbErr: unknown) {
          const cbErrorObj = cbErr instanceof Error ? cbErr : new Error(String(cbErr));
          console.error(
            `[Volidator] Error in onDeliveryFailure callback during batch failure: ${cbErrorObj.message}`,
          );
        }
      }
      return { accepted: 0, rejected: rejected + preparedEntries.length };
    }
  }

  // ---------------------------------------------------------------------------
  // batcher() — Convenience batcher for buffered log ingestion
  // ---------------------------------------------------------------------------
  /**
   * Creates a convenience batcher instance for buffering and ingestion.
   *
   * ⚠️ SERVERLESS/EDGE CAVEAT:
   * autoFlushInterval uses setInterval internally. In serverless/edge environments
   * (e.g. Cloudflare Workers, Vercel Edge), the V8 isolate is frozen or destroyed
   * once the response is sent. Background timers will silently fail to fire, leading
   * to dropped logs. Only use autoFlushInterval in long-lived Node.js processes.
   * In serverless/edge environments, always call await batcher.flush() explicitly
   * before returning the response, or wrap it in ctx.waitUntil().
   */
  public batcher(options?: BatcherOptions): VolidatorBatcher {
    let buffer: LogPayload[] = [];
    let intervalId: any = null;

    const flush = async (): Promise<{ accepted: number; rejected: number }> => {
      if (intervalId) {
        clearInterval(intervalId);
        intervalId = null;
      }
      if (buffer.length === 0) {
        if (options?.autoFlushInterval) {
          startTimer();
        }
        return { accepted: 0, rejected: 0 };
      }

      const payloadsToFlush = [...buffer];
      buffer = [];

      if (options?.autoFlushInterval) {
        startTimer();
      }

      return this.logBatch(payloadsToFlush);
    };

    const startTimer = () => {
      if (options?.autoFlushInterval && !intervalId) {
        intervalId = setInterval(() => {
          flush().catch((err) => {
            console.error(`[Volidator] Batcher auto-flush failed: ${err.message}`);
          });
        }, options.autoFlushInterval);
        if (intervalId && typeof intervalId.unref === "function") {
          intervalId.unref();
        }
      }
    };

    const push = (payload: LogPayload): void => {
      buffer.push(payload);
      const maxCount = options?.autoFlushCount || 100;
      if (buffer.length >= Math.min(maxCount, 100)) {
        flush().catch((err) => {
          console.error(`[Volidator] Batcher auto-flush on count failed: ${err.message}`);
        });
      }
    };

    const size = (): number => buffer.length;

    startTimer();

    return {
      push,
      flush,
      size,
    };
  }

  // ---------------------------------------------------------------------------
  // generateEmbedToken() — Sign a HS256 JWT for the embeddable dashboard widget
  // ---------------------------------------------------------------------------
  async generateEmbedToken(
    config: EmbedTokenConfig & {
      projectId?: string;
      clientSecret?: string;
    },
  ): Promise<EmbedTokenResult> {
    const projectId = config.projectId || this.projectId;
    const clientSecret = config.clientSecret || this.clientSecret;

    if (!projectId || !clientSecret) {
      throw new Error(
        "generateEmbedToken() requires projectId and clientSecret to be provided in either the configuration or the VolidatorClient constructor.",
      );
    }

    const {
      actorId,
      targetId,
      tenantId,
      scope,
      expiresIn = "2h",
      dashboardUrl = "https://dash.volidator.com",
      hostOrigin,
      view,
    } = config;

    // Determine default query scope based on parameters
    const defaultScope = scope || (tenantId ? "tenant" : "actor");

    // Check if at least one identity parameter is provided (bypassed for auditor scope)
    if (defaultScope !== "auditor" && !actorId && !targetId && !tenantId) {
      throw new Error(
        "At least one of actorId, targetId, or tenantId must be provided to generateEmbedToken().",
      );
    }

    // 1. Compute blind indexes for all keys in the keyring
    const actorBlindIndexes = actorId
      ? await Promise.all(
          Object.keys(this.keyring).map(async (id) =>
            this.generateBlindIndex(actorId, await this._getHashedKey(id)),
          ),
        )
      : undefined;
    const targetBlindIndexes = targetId
      ? await Promise.all(
          Object.keys(this.keyring).map(async (id) =>
            this.generateBlindIndex(targetId, await this._getHashedKey(id)),
          ),
        )
      : undefined;
    const tenantBlindIndexes = tenantId
      ? await Promise.all(
          Object.keys(this.keyring).map(async (id) =>
            this.generateBlindIndex(tenantId, await this._getHashedKey(id)),
          ),
        )
      : undefined;

    // 2. Resolve expiry to seconds, capping it at 1 hour (3600s) for security.
    const parsedExpiry = this.parseExpiry(expiresIn);
    const maxExpiry = defaultScope === "auditor" ? 604800 : 3600;
    const expiresInSeconds = Math.min(parsedExpiry, maxExpiry);
    const now = Math.floor(Date.now() / 1000);

    // 3. Build the JWT payload
    const payload: Record<string, any> = {
      pid: projectId,
      scope: defaultScope,
      iat: now,
      exp: now + expiresInSeconds,
    };

    if (actorBlindIndexes) payload.abi = actorBlindIndexes;
    if (targetBlindIndexes) payload.tgb = targetBlindIndexes;
    if (tenantBlindIndexes) payload.tbi = tenantBlindIndexes;

    // Compresses presentation config to minimize cookie/header footprint
    if (view) {
      const compressed: Record<string, any> = {};
      if (Array.isArray(view.columns)) {
        compressed.cols = view.columns.map((col) => {
          if (col === "createdAt") return "cat";
          if (col === "actor") return "act";
          if (col === "action") return "acn";
          if (col === "target") return "tgt";
          if (col.startsWith("metadata.")) {
            return `m.${col.slice(9)}`;
          }
          return col;
        });
      }
      if (view.defaultFilter) {
        compressed.flt = {};
        if (view.defaultFilter.search !== undefined) {
          compressed.flt.q = view.defaultFilter.search;
        }
        if (view.defaultFilter.action !== undefined) {
          compressed.flt.act = view.defaultFilter.action;
        }
      }
      payload.view = compressed;
    }

    // 4. Sign as HS256 JWT using the SHA-256 hash of the project's clientSecret to preserve ZK model
    const clientSecretHash = await this.sha256(clientSecret);
    const token = await this.signHS256JWT(payload, clientSecretHash);

    // 5. Append the keyring as the URL hash fragment
    const keyringString = Object.entries(this.keyring)
      .map(([id, key]) => `${id}:${key}`)
      .join(",");
    const hostParam = hostOrigin ? `?host=${encodeURIComponent(hostOrigin)}` : "";
    const embedUrl = `${dashboardUrl}/embed/${token}${hostParam}#${keyringString}`;

    return { token, embedUrl };
  }

  private async sha256(text: string): Promise<string> {
    const buf = new TextEncoder().encode(text);
    const hash = await globalThis.crypto.subtle.digest("SHA-256", buf);
    return Array.from(new Uint8Array(hash))
      .map((b) => b.toString(16).padStart(2, "0"))
      .join("");
  }

  private async signHS256JWT(payload: object, secret: string): Promise<string> {
    const header = { alg: "HS256", typ: "JWT" };

    const encode = (obj: object) =>
      btoa(JSON.stringify(obj)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

    const unsigned = `${encode(header)}.${encode(payload)}`;

    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret) as unknown as BufferSource,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"],
    );
    const signatureBuffer = await globalThis.crypto.subtle.sign(
      "HMAC",
      key,
      new TextEncoder().encode(unsigned),
    );

    let binary = "";
    const arr = new Uint8Array(signatureBuffer);
    for (let i = 0; i < arr.byteLength; i++) {
      binary += String.fromCharCode(arr[i]);
    }
    const signature = btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

    return `${unsigned}.${signature}`;
  }

  private parseExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)(s|m|h|d)$/);
    if (!match) return 7200;
    const [, num, unit] = match;
    const n = parseInt(num, 10);
    switch (unit) {
      case "s":
        return n;
      case "m":
        return n * 60;
      case "h":
        return n * 3600;
      case "d":
        return n * 86400;
      default:
        return 7200;
    }
  }

  /**
   * Request WebAuthn biometric action attestation for a high-risk action.
   * Prompts the browser for TouchID/FaceID/YubiKey and returns the attestation bundle.
   */
  async attestHumanAction(payload: {
    action: string;
    target?: string;
    metadata?: Record<string, any>;
  }): Promise<{
    challenge: string;
    signature: string;
    authenticatorData: string;
    clientDataJSON: string;
    credentialId: string;
  }> {
    const res = await fetch(`${this.endpoint}/v1/attestation/challenge`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      throw new Error(`Failed to retrieve attestation challenge: ${res.statusText}`);
    }

    const { challenge } = (await res.json()) as { challenge: string };

    const canonicalStr = canonicalize({
      action: payload.action,
      target: payload.target || null,
      metadata: payload.metadata || null,
    });

    const encoder = new TextEncoder();
    const data = encoder.encode(canonicalStr);
    const hashBuffer = await globalThis.crypto.subtle.digest("SHA-256", data);
    const hashArray = new Uint8Array(hashBuffer);

    const challengeBytes = encoder.encode(challenge);

    const finalChallengeBytes = new Uint8Array(challengeBytes.length + 1 + hashArray.length);
    finalChallengeBytes.set(challengeBytes, 0);
    finalChallengeBytes[challengeBytes.length] = 58; // ":" character
    finalChallengeBytes.set(hashArray, challengeBytes.length + 1);

    const finalHashBuffer = await globalThis.crypto.subtle.digest("SHA-256", finalChallengeBytes);
    const webauthnChallengeBytes = new Uint8Array(finalHashBuffer);

    if (typeof window === "undefined" || !window.navigator?.credentials) {
      throw new Error(
        "Action Attestation is only supported in browser environments with WebAuthn.",
      );
    }

    const credential = (await window.navigator.credentials.get({
      publicKey: {
        challenge: webauthnChallengeBytes,
        timeout: 900000, // 15 minutes
        userVerification: "required",
      },
    })) as any;

    if (!credential) {
      throw new Error("Biometric assertion failed or cancelled by user.");
    }

    const bufferToBase64url = (buf: ArrayBuffer): string => {
      const bytes = new Uint8Array(buf);
      let binary = "";
      for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
      }
      return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    };

    return {
      challenge,
      signature: bufferToBase64url(credential.response.signature),
      authenticatorData: bufferToBase64url(credential.response.authenticatorData),
      clientDataJSON: bufferToBase64url(credential.response.clientDataJSON),
      credentialId: credential.id,
    };
  }

  /**
   * Purge (tombstone) all logs associated with a specific customer (actorId).
   * Generates the actor's blind index client-side and requests deletion from the edge.
   */
  async purgeActorLogs(
    actorId: string,
    options?: {
      sessionToken?: string;
      webauthn?: {
        challenge: string;
        signature: string;
        authenticatorData: string;
        clientDataJSON: string;
        credentialId: string;
        maxCreatedAt: string;
      };
    }
  ): Promise<{ deletedCount: number }> {
    const activeKeyBuffer = await this._getHashedKey(this.activeKeyId);
    const actorBlindIndex = await this.generateBlindIndex(actorId, activeKeyBuffer);

    const body = options
      ? {
          sessionToken: options.sessionToken,
          ...options.webauthn,
        }
      : undefined;

    const res = await fetch(
      `${this.endpoint}/v1/projects/${this.projectId}/actors/${actorBlindIndex}`,
      {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          ...(body ? { "Content-Type": "application/json" } : {}),
        },
        body: body ? JSON.stringify(body) : undefined,
      }
    );

    if (!res.ok) {
      const errText = await res.text();
      throw new Error(`Failed to purge actor logs: ${res.statusText} (${errText})`);
    }

    return (await res.json()) as { deletedCount: number };
  }
}

// ---------------------------------------------------------------------------
// Standard Compliance Logging Helper Class
// ---------------------------------------------------------------------------
export class VolidatorCompliance {
  private client: VolidatorClient;

  constructor(client: VolidatorClient) {
    this.client = client;
  }

  private async logWithControl(
    action: string,
    soc2Control: string,
    isoControl: string,
    payload: Omit<LogPayload, "action">,
  ): Promise<boolean> {
    const metadata = {
      ...payload.metadata,
      soc2_control: soc2Control,
      iso27001: isoControl,
    };
    return this.client.log({
      ...payload,
      action,
      metadata,
    });
  }

  async accessRevoked(payload: Omit<LogPayload, "action">): Promise<boolean> {
    return this.logWithControl("access.revoked", "CC6.1", "A.9.2.6", payload);
  }

  async accessGranted(payload: Omit<LogPayload, "action">): Promise<boolean> {
    return this.logWithControl("access.granted", "CC6.1", "A.9.2.1", payload);
  }

  async dataExported(payload: Omit<LogPayload, "action">): Promise<boolean> {
    return this.logWithControl("data.exported", "CC6.6", "A.12.4.1", payload);
  }

  async systemConfigChanged(payload: Omit<LogPayload, "action">): Promise<boolean> {
    return this.logWithControl("system.config_changed", "CC6.2", "A.12.1.2", payload);
  }

  async mfaEnabled(payload: Omit<LogPayload, "action">): Promise<boolean> {
    return this.logWithControl("mfa.enabled", "CC6.3", "A.9.4.2", payload);
  }
}

// ---------------------------------------------------------------------------
// AI & Autonomous Agent Compliance Audit Taxonomy Class
// ---------------------------------------------------------------------------
export class VolidatorAgent {
  private client: VolidatorClient;

  constructor(client: VolidatorClient) {
    this.client = client;
  }

  private async logAgent(
    action: string,
    euAiAct: string,
    nistAiRmf: string,
    soc2Control: string,
    isoControl: string,
    payload: Omit<LogPayload, "action"> & Record<string, any>,
  ): Promise<boolean> {
    const {
      actor,
      actorId,
      target,
      targetId,
      tenant,
      tenantId,
      metadata,
      context,
      telemetry,
      req,
      traceId,
      spanId,
      parentSpanId,
      ...agentData
    } = payload;

    const enrichedMetadata = {
      ...metadata,
      ...agentData,
      eu_ai_act: euAiAct,
      nist_ai_rmf: nistAiRmf,
      soc2_control: soc2Control,
      iso27001: isoControl,
    };

    // Use 64KB metadata limit for AI events
    return this.client.log(
      {
        actor,
        actorId,
        target,
        targetId,
        tenant,
        tenantId,
        action,
        metadata: enrichedMetadata,
        context,
        telemetry,
        req,
        traceId,
        spanId,
        parentSpanId,
      },
      5242880,
    );
  }

  /**
   * Logs a tool call or external API invocation by an agent.
   * Maps to EU AI Act Article 12, NIST AI RMF MANAGE 2.2, SOC2 CC6.6, ISO 27001 A.12.4.1.
   */
  async toolCall(
    payload: Omit<LogPayload, "action"> & {
      toolName: string;
      toolInput?: Record<string, any>;
      toolOutput?: Record<string, any>;
      latencyMs?: number;
      success: boolean;
    },
  ): Promise<boolean> {
    return this.logAgent(
      "agent.tool_call",
      "Article 12",
      "MANAGE 2.2",
      "CC6.6",
      "A.12.4.1",
      payload,
    );
  }

  /**
   * Logs a key decision made autonomously by an AI agent model.
   * Maps to EU AI Act Article 12 & 13, NIST AI RMF GOVERN 1.7, SOC2 CC6.2, ISO 27001 A.18.1.3.
   */
  async decision(
    payload: Omit<LogPayload, "action"> & {
      decision: string;
      alternatives?: string[];
      rationale?: string;
      confidenceScore?: number;
      modelId?: string;
    },
  ): Promise<boolean> {
    return this.logAgent(
      "agent.decision",
      "Article 12 & 13",
      "GOVERN 1.7",
      "CC6.2",
      "A.18.1.3",
      payload,
    );
  }

  /**
   * Logs a request for human review or permission escalation.
   * Maps to EU AI Act Article 14, NIST AI RMF GOVERN 5.1, SOC2 CC6.3, ISO 27001 A.6.1.2.
   */
  async escalation(
    payload: Omit<LogPayload, "action"> & {
      reason: string;
      urgency?: "low" | "medium" | "high";
      blockedAction?: string;
    },
  ): Promise<boolean> {
    return this.logAgent(
      "agent.escalation",
      "Article 14",
      "GOVERN 5.1",
      "CC6.3",
      "A.6.1.2",
      payload,
    );
  }

  /**
   * Logs anomalous environment inputs, potential prompt injections, or policy violations.
   * Maps to EU AI Act Article 9, NIST AI RMF MANAGE 2.4, SOC2 CC7.2, ISO 27001 A.16.1.2.
   */
  async anomaly(
    payload: Omit<LogPayload, "action"> & {
      description: string;
      severity?: "low" | "medium" | "high" | "critical";
      anomalyType?: "prompt_injection" | "unexpected_input" | "policy_violation" | "other";
    },
  ): Promise<boolean> {
    return this.logAgent("agent.anomaly", "Article 9", "MANAGE 2.4", "CC7.2", "A.16.1.2", payload);
  }

  /**
   * Logs a model refusal to execute a user prompt or command due to alignment safety.
   * Maps to EU AI Act Article 5, NIST AI RMF GOVERN 1.1, SOC2 CC6.8, ISO 27001 A.18.1.3.
   */
  async refusal(
    payload: Omit<LogPayload, "action"> & {
      refusedInstruction: string;
      reason: string;
      policyViolated?: string;
    },
  ): Promise<boolean> {
    return this.logAgent("agent.refusal", "Article 5", "GOVERN 1.1", "CC6.8", "A.18.1.3", payload);
  }

  /**
   * Logs an execution context handoff from one agent to another.
   * Maps to EU AI Act Article 12, NIST AI RMF MAP 1.6, SOC2 CC6.6, ISO 27001 A.12.4.1.
   */
  async handoff(
    payload: Omit<LogPayload, "action"> & {
      toAgentId: string;
      instruction: string;
      agentContext?: Record<string, any>;
    },
  ): Promise<boolean> {
    return this.logAgent("agent.handoff", "Article 12", "MAP 1.6", "CC6.6", "A.12.4.1", payload);
  }
}

function canonicalize(obj: any): string {
  if (obj === undefined) return "";
  if (obj === null) return "null";
  if (typeof obj !== "object") {
    return JSON.stringify(obj);
  }
  if (obj instanceof Date) {
    return JSON.stringify(obj.toJSON());
  }
  if (Array.isArray(obj)) {
    const items = obj.map((item) => {
      const val = canonicalize(item);
      return val === "" ? "null" : val;
    });
    return "[" + items.join(",") + "]";
  }
  const keys = Object.keys(obj).sort();
  const pairs: string[] = [];
  for (const k of keys) {
    const val = obj[k];
    if (val === undefined || typeof val === "function" || typeof val === "symbol") {
      continue;
    }
    pairs.push(JSON.stringify(k) + ":" + canonicalize(val));
  }
  return "{" + pairs.join(",") + "}";
}
