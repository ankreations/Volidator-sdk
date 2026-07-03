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
export type EnforceReference<TData, TRefKeys extends keyof TData> =
  Omit<TData, TRefKeys> & { [K in TRefKeys]: ReferencePayload };

export interface TelemetryConfig {
  preset?: "strict" | "standard" | "full";
  ip?: "track" | "anonymize" | "skip";
  userAgent?: "track" | "parse" | "skip";
  location?: boolean;
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
  req?: any; // support passing the HTTP request object directly
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
     */
    maxMetadataSize?: number;
  }) {
    this.apiKey = config.apiKey;
    this.endpoint = config.endpoint || "https://ingestion.volidator.com";
    this.projectId = config.projectId;
    this.clientSecret = config.clientSecret;
    this.redactKeys = config.redactKeys || [];
    this.referenceKeys = config.referenceKeys || [];
    this.maxMetadataSize = config.maxMetadataSize || 10240;

    // Parse encryption keys & keyring
    if (config.keyring && config.activeEncryptionKeyId) {
      this.keyring = config.keyring;
      this.activeKeyId = config.activeEncryptionKeyId;
    } else if (config.encryptionKey) {
      this.activeKeyId = "v1";
      this.keyring = { "v1": config.encryptionKey };
    } else {
      throw new Error("Either encryptionKey OR (keyring AND activeEncryptionKeyId) must be provided in VolidatorClient constructor.");
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
    this.telemetryConfig = VolidatorClient.resolveTelemetryConfig(config.telemetry || { preset: "standard" });
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

    const rawIp = getHeader("cf-connecting-ip") ||
      getHeader("x-real-ip") ||
      getHeader("x-forwarded-for");

    const ip = rawIp ? rawIp.split(",")[0].trim() : (req?.socket?.remoteAddress || "");
    const userAgent = getHeader("user-agent");

    return {
      ip,
      userAgent,
      location: {
        country: getHeader("cf-ipcountry") || getHeader("x-vercel-ip-country") || "",
        region: getHeader("cf-region-code") || getHeader("x-vercel-ip-country-region") || "",
        city: getHeader("cf-ipcity") || getHeader("x-vercel-ip-city") || "",
      }
    };
  }

  // ---------------------------------------------------------------------------
  // OpenTelemetry W3C traceparent context parser
  // ---------------------------------------------------------------------------
  static extractTraceContext(req: any): { traceId?: string; spanId?: string } {
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

    const traceparent = getHeader("traceparent");
    if (!traceparent) return {};
    const parts = traceparent.split("-");
    if (parts.length !== 4) return {};
    return { traceId: parts[1], spanId: parts[2] };
  }

  private static resolveTelemetryConfig(config: TelemetryConfig): Required<Omit<TelemetryConfig, "preset">> {
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
        type: "Server"
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
      const match = ua.match(/(?:chrome|crios)\/([0-9\.]+)/i);
      browser = `Chrome ${match ? match[1].split('.')[0] : ""}`.trim();
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
      "raw", keyBuffer as unknown as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const signature = await globalThis.crypto.subtle.sign(
      "HMAC", key, new TextEncoder().encode(value)
    );
    return Array.from(new Uint8Array(signature))
      .map(b => b.toString(16).padStart(2, "0"))
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
      "raw", activeHashedKey as unknown as BufferSource, { name: "AES-GCM" }, false, ["encrypt"]
    );

    const encryptedBuffer = await globalThis.crypto.subtle.encrypt(
      { name: "AES-GCM", iv }, cryptoKey, new TextEncoder().encode(text)
    );

    const finalBuffer = new Uint8Array(iv.length + encryptedBuffer.byteLength);
    finalBuffer.set(iv, 0);
    finalBuffer.set(new Uint8Array(encryptedBuffer), iv.length);

    // Convert to base64 safely for edges
    let binary = '';
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
    const extractId = (v: string | ReferencePayload): string =>
      typeof v === "object" ? v.id : v;

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
        const isFull = payload.telemetry?.preset === "full" || (!payload.telemetry && this.telemetryConfig.ip === "track");
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
      if (this.referenceKeys.includes(metaKey) && typeof v === "object" && v !== null && "id" in v) {
        safeMetadata[k] = `[REF:${(v as ReferencePayload).id}]`;
      } else if (this.redactKeys.includes(metaKey) && typeof v === "string") {
        safeMetadata[k] = `[REDACTED:${k}]`;
      } else {
        safeMetadata[k] = v;
      }
    }

    const limitDepth = (obj: any, currentDepth = 1): any => {
      if (currentDepth > 5) {
        return "[Truncated - Depth Exceeded]";
      }
      if (typeof obj !== "object" || obj === null) {
        if (typeof obj === "string") {
          return truncate(obj, 1000);
        }
        return obj;
      }
      if (Array.isArray(obj)) {
        return obj.map(item => limitDepth(item, currentDepth + 1));
      }
      const result: Record<string, any> = {};
      for (const [key, val] of Object.entries(obj)) {
        result[key] = limitDepth(val, currentDepth + 1);
      }
      return result;
    };

    const processedMetadata = limitDepth(safeMetadata);
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

    // Auto-extract trace contexts
    let traceId = payload.traceId;
    let spanId = payload.spanId;
    let parentSpanId = payload.parentSpanId;

    if (payload.req) {
      const extractedTrace = VolidatorClient.extractTraceContext(payload.req);
      if (!traceId && extractedTrace.traceId) {
        traceId = extractedTrace.traceId;
      }
      if (!spanId && extractedTrace.spanId) {
        spanId = extractedTrace.spanId;
      }
    }

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
    const tenantBlindIndex = tenant ? await this.generateBlindIndex(tenant, activeKeyBuffer) : undefined;
    const traceBlindIndex = traceId ? await this.generateBlindIndex(traceId, activeKeyBuffer) : undefined;

    const encryptedPayload = await this.encryptPayload(enrichedPayload);

    return {
      actorBlindIndex,
      actionBlindIndex,
      targetBlindIndex,
      tenantBlindIndex,
      traceBlindIndex,
      encryptedPayload,
    };
  }

  // ---------------------------------------------------------------------------
  // log() — Encrypt and ingest a single audit event
  // ---------------------------------------------------------------------------
  async log(payload: LogPayload, maxMetaOverride?: number): Promise<boolean> {
    const entry = await this.prepareLogEntry(payload, maxMetaOverride);
    try {
      const res = await fetch(`${this.endpoint}/v1/log`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify(entry),
      });

      return res.ok;
    } catch (err: any) {
      console.error(`[Volidator] Failed to send log: ${err.message}`);
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // logBatch() — Bulk encrypt and ingest a batch of up to 100 audit events
  // ---------------------------------------------------------------------------
  async logBatch(payloads: LogPayload[], maxMetaOverride?: number): Promise<{ accepted: number; rejected: number }> {
    if (!Array.isArray(payloads) || payloads.length === 0) {
      return { accepted: 0, rejected: 0 };
    }

    // Cap batch size at 100
    const batch = payloads.slice(0, 100);
    const preparedEntries: any[] = [];
    let rejected = payloads.length - batch.length;

    const results = await Promise.allSettled(
      batch.map(p => this.prepareLogEntry(p, maxMetaOverride))
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
      const res = await fetch(`${this.endpoint}/v1/logs/batch`, {
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
    } catch (err: any) {
      console.error(`[Volidator] Failed to send log batch: ${err.message}`);
      return { accepted: 0, rejected: rejected + preparedEntries.length };
    }
  }

  // ---------------------------------------------------------------------------
  // generateEmbedToken() — Sign a HS256 JWT for the embeddable dashboard widget
  // ---------------------------------------------------------------------------
  async generateEmbedToken(config: EmbedTokenConfig): Promise<EmbedTokenResult> {
    if (!this.projectId || !this.clientSecret) {
      throw new Error(
        "generateEmbedToken() requires projectId and clientSecret in the VolidatorClient constructor."
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
        "At least one of actorId, targetId, or tenantId must be provided to generateEmbedToken()."
      );
    }

    // 1. Compute blind indexes for all keys in the keyring
    const actorBlindIndexes = actorId
      ? await Promise.all(Object.keys(this.keyring).map(async id => this.generateBlindIndex(actorId, await this._getHashedKey(id))))
      : undefined;
    const targetBlindIndexes = targetId
      ? await Promise.all(Object.keys(this.keyring).map(async id => this.generateBlindIndex(targetId, await this._getHashedKey(id))))
      : undefined;
    const tenantBlindIndexes = tenantId
      ? await Promise.all(Object.keys(this.keyring).map(async id => this.generateBlindIndex(tenantId, await this._getHashedKey(id))))
      : undefined;

    // 2. Resolve expiry to seconds, capping it at 1 hour (3600s) for security.
    const parsedExpiry = this.parseExpiry(expiresIn);
    const maxExpiry = defaultScope === "auditor" ? 604800 : 3600;
    const expiresInSeconds = Math.min(parsedExpiry, maxExpiry);
    const now = Math.floor(Date.now() / 1000);

    // 3. Build the JWT payload
    const payload: Record<string, any> = {
      pid: this.projectId,
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

    // 4. Sign as HS256 JWT using the project's clientSecret
    const token = await this.signHS256JWT(payload, this.clientSecret);

    // 5. Append the keyring as the URL hash fragment
    const keyringString = Object.entries(this.keyring)
      .map(([id, key]) => `${id}:${key}`)
      .join(",");
    const hostParam = hostOrigin
      ? `?host=${encodeURIComponent(hostOrigin)}`
      : "";
    const embedUrl = `${dashboardUrl}/embed/${token}${hostParam}#${keyringString}`;

    return { token, embedUrl };
  }

  private async signHS256JWT(payload: object, secret: string): Promise<string> {
    const header = { alg: "HS256", typ: "JWT" };

    const encode = (obj: object) =>
      btoa(JSON.stringify(obj))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");

    const unsigned = `${encode(header)}.${encode(payload)}`;

    const key = await globalThis.crypto.subtle.importKey(
      "raw", new TextEncoder().encode(secret) as unknown as BufferSource, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
    );
    const signatureBuffer = await globalThis.crypto.subtle.sign(
      "HMAC", key, new TextEncoder().encode(unsigned)
    );

    let binary = '';
    const arr = new Uint8Array(signatureBuffer);
    for (let i = 0; i < arr.byteLength; i++) {
      binary += String.fromCharCode(arr[i]);
    }
    const signature = btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    return `${unsigned}.${signature}`;
  }

  private parseExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)(s|m|h|d)$/);
    if (!match) return 7200;
    const [, num, unit] = match;
    const n = parseInt(num, 10);
    switch (unit) {
      case "s": return n;
      case "m": return n * 60;
      case "h": return n * 3600;
      case "d": return n * 86400;
      default: return 7200;
    }
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
    payload: Omit<LogPayload, "action">
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
    payload: Omit<LogPayload, "action"> & Record<string, any>
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
      65536
    );
  }

  /**
   * Logs a tool call or external API invocation by an agent.
   * Maps to EU AI Act Article 12, NIST AI RMF MANAGE 2.2, SOC2 CC6.6, ISO 27001 A.12.4.1.
   */
  async toolCall(payload: Omit<LogPayload, "action"> & {
    toolName: string;
    toolInput?: Record<string, any>;
    toolOutput?: Record<string, any>;
    latencyMs?: number;
    success: boolean;
  }): Promise<boolean> {
    return this.logAgent("agent.tool_call", "Article 12", "MANAGE 2.2", "CC6.6", "A.12.4.1", payload);
  }

  /**
   * Logs a key decision made autonomously by an AI agent model.
   * Maps to EU AI Act Article 12 & 13, NIST AI RMF GOVERN 1.7, SOC2 CC6.2, ISO 27001 A.18.1.3.
   */
  async decision(payload: Omit<LogPayload, "action"> & {
    decision: string;
    alternatives?: string[];
    rationale?: string;
    confidenceScore?: number;
    modelId?: string;
  }): Promise<boolean> {
    return this.logAgent("agent.decision", "Article 12 & 13", "GOVERN 1.7", "CC6.2", "A.18.1.3", payload);
  }

  /**
   * Logs a request for human review or permission escalation.
   * Maps to EU AI Act Article 14, NIST AI RMF GOVERN 5.1, SOC2 CC6.3, ISO 27001 A.6.1.2.
   */
  async escalation(payload: Omit<LogPayload, "action"> & {
    reason: string;
    urgency?: "low" | "medium" | "high";
    blockedAction?: string;
  }): Promise<boolean> {
    return this.logAgent("agent.escalation", "Article 14", "GOVERN 5.1", "CC6.3", "A.6.1.2", payload);
  }

  /**
   * Logs anomalous environment inputs, potential prompt injections, or policy violations.
   * Maps to EU AI Act Article 9, NIST AI RMF MANAGE 2.4, SOC2 CC7.2, ISO 27001 A.16.1.2.
   */
  async anomaly(payload: Omit<LogPayload, "action"> & {
    description: string;
    severity?: "low" | "medium" | "high" | "critical";
    anomalyType?: "prompt_injection" | "unexpected_input" | "policy_violation" | "other";
  }): Promise<boolean> {
    return this.logAgent("agent.anomaly", "Article 9", "MANAGE 2.4", "CC7.2", "A.16.1.2", payload);
  }

  /**
   * Logs a model refusal to execute a user prompt or command due to alignment safety.
   * Maps to EU AI Act Article 5, NIST AI RMF GOVERN 1.1, SOC2 CC6.8, ISO 27001 A.18.1.3.
   */
  async refusal(payload: Omit<LogPayload, "action"> & {
    refusedInstruction: string;
    reason: string;
    policyViolated?: string;
  }): Promise<boolean> {
    return this.logAgent("agent.refusal", "Article 5", "GOVERN 1.1", "CC6.8", "A.18.1.3", payload);
  }

  /**
   * Logs an execution context handoff from one agent to another.
   * Maps to EU AI Act Article 12, NIST AI RMF MAP 1.6, SOC2 CC6.6, ISO 27001 A.12.4.1.
   */
  async handoff(payload: Omit<LogPayload, "action"> & {
    toAgentId: string;
    instruction: string;
    agentContext?: Record<string, any>;
  }): Promise<boolean> {
    return this.logAgent("agent.handoff", "Article 12", "MAP 1.6", "CC6.6", "A.12.4.1", payload);
  }
}
