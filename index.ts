import { createHmac, createHash, createCipheriv, randomBytes } from "crypto";

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
  actor?: string;
  actorId?: string; // support actorId as alias
  action: string;
  target?: string;
  targetId?: string; // support targetId as alias
  metadata?: Record<string, any>;
  context?: TelemetryContext;
  telemetry?: TelemetryConfig;
  req?: any; // support passing the HTTP request object directly
}

interface EmbedTokenConfig {
  /** The plaintext actor identifier (e.g. "usr_123") */
  actorId: string;
  /** Duration string: "30m", "2h", "7d". Defaults to "2h". */
  expiresIn?: string;
  /** Base URL of the Volidator dashboard. Defaults to "https://dash.volidator.com". */
  dashboardUrl?: string;
}

interface EmbedTokenResult {
  token: string;
  embedUrl: string;
}

export class VolidatorClient {
  private apiKey: string;
  private encryptionKey: string;
  private endpoint: string;
  private hashedKey: Buffer;
  private telemetryConfig: Required<Omit<TelemetryConfig, "preset">>;

  // Optional fields required only for generateEmbedToken()
  private projectId?: string;
  private clientSecret?: string;

  /**
   * Keys whose values should be scrubbed (replaced with [REDACTED:<key>]) before encryption.
   *
   * Supported scopes:
   *   - Top-level fields: "actor", "target"
   *   - Metadata fields:  "metadata.email", "metadata.ssn", "metadata.phone", etc.
   *
   * Example:
   *   redactKeys: ["actor", "metadata.email", "metadata.ssn"]
   *
   * Why this works: Volidator encrypts the entire payload client-side. By scrubbing
   * PII *before* encryption, the plaintext never contains sensitive data — satisfying
   * HIPAA, GDPR, and SOC2 requirements with zero NLP/AI and zero performance cost.
   */
  private redactKeys: string[];

  constructor(config: {
    apiKey: string;
    encryptionKey: string;
    endpoint?: string;
    // Provide these when you need to generate embed tokens server-side
    projectId?: string;
    clientSecret?: string;
    telemetry?: TelemetryConfig;
    /**
     * Fields to redact before encryption. Supports top-level fields ("actor", "target")
     * and nested metadata fields ("metadata.email", "metadata.ssn", "metadata.phone").
     * Redacted values become "[REDACTED:<fieldName>]" in the encrypted payload.
     */
    redactKeys?: string[];
  }) {
    this.apiKey = config.apiKey;
    this.encryptionKey = config.encryptionKey;
    this.endpoint = config.endpoint || "https://ingestion.volidator.com";
    this.projectId = config.projectId;
    this.clientSecret = config.clientSecret;
    this.redactKeys = config.redactKeys || [];
    // Derive a 256-bit key from the client encryption key (matches SDK & browser WebCrypto)
    this.hashedKey = createHash("sha256").update(config.encryptionKey).digest();

    // Default to 'standard' preset if nothing is provided
    this.telemetryConfig = VolidatorClient.resolveTelemetryConfig(config.telemetry || { preset: "standard" });
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
  // Blind Index — deterministic HMAC-SHA256 for searchable encrypted fields
  // ---------------------------------------------------------------------------
  private generateBlindIndex(value: string): string {
    return createHmac("sha256", this.hashedKey).update(value).digest("hex");
  }

  // ---------------------------------------------------------------------------
  // Payload Encryption — AES-256-GCM with prepended 12-byte IV
  // Layout: [IV (12B)] [Ciphertext] [Auth Tag (16B)]
  // ---------------------------------------------------------------------------
  private async encryptPayload(payload: object): Promise<string> {
    const text = JSON.stringify(payload);
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.hashedKey, iv);

    const ciphertext = Buffer.concat([
      cipher.update(text, "utf8"),
      cipher.final(),
    ]);
    const tag = cipher.getAuthTag();

    const finalBuffer = Buffer.concat([iv, ciphertext, tag]);
    return finalBuffer.toString("base64");
  }

  // ---------------------------------------------------------------------------
  // log() — Encrypt and ingest a single audit event
  // ---------------------------------------------------------------------------
  async log(payload: LogPayload): Promise<boolean> {
    const actor = payload.actor || payload.actorId || "unknown";
    const action = payload.action;
    const target = payload.target || payload.targetId || "unknown";

    // Merge instance telemetry configuration with log-level override
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

    // 1. Location
    if (logTelemetry.location) {
      context.location = {};
      if (payloadCtx.location) {
        context.location.country = payloadCtx.location.country || "";
        context.location.region = payloadCtx.location.region || "";
        // Standard drops city level, Full preset keeps city level
        const isFull = payload.telemetry?.preset === "full" || (!payload.telemetry && this.telemetryConfig.ip === "track");
        if (logTelemetry.ip === "track" || isFull) {
          context.location.city = payloadCtx.location.city || "";
        }
      }
    }

    // 2. IP Address
    if (logTelemetry.ip === "anonymize" && rawIp) {
      // One-way salt and hash using client's encryptionKey as salt
      context.ip = createHmac("sha256", this.encryptionKey)
        .update(rawIp)
        .digest("hex");
    } else if (logTelemetry.ip === "track" && rawIp) {
      context.ip = rawIp;
    }

    // 3. User-Agent
    if (logTelemetry.userAgent !== "skip") {
      if (rawUa) {
        context.device = this.parseUserAgent(rawUa);
        if (logTelemetry.userAgent === "track") {
          context.userAgent = rawUa;
        }
      } else if (payloadCtx.device) {
        context.device = payloadCtx.device;
      }
    }

    // ── PII/PHI Redaction ────────────────────────────────────────────────────
    // Apply redactKeys rules BEFORE building the encrypted payload.
    // Blind indexes are computed from the original value so filtered queries
    // still work; only the stored plaintext is scrubbed.
    const scrub = (value: string, key: string): string =>
      this.redactKeys.includes(key) ? `[REDACTED:${key}]` : value;

    // Scrub top-level fields
    const safeActor  = scrub(actor,  "actor");
    const safeTarget = scrub(target, "target");

    // Scrub metadata fields (supports "metadata.fieldName" notation)
    const rawMetadata = payload.metadata || {};
    const safeMetadata: Record<string, any> = {};
    for (const [k, v] of Object.entries(rawMetadata)) {
      const metaKey = `metadata.${k}`;
      safeMetadata[k] = this.redactKeys.includes(metaKey) && typeof v === "string"
        ? `[REDACTED:${k}]`
        : v;
    }

    // Construct final plaintext payload before encrypting
    const enrichedPayload: any = {
      actor:    safeActor,
      action,
      target:   safeTarget,
      metadata: safeMetadata,
    };

    if (Object.keys(context).length > 0) {
      enrichedPayload.context = context;
    }

    // Blind indexes are derived from the ORIGINAL values so searchability is preserved
    const actorBlindIndex = this.generateBlindIndex(actor);
    const actionBlindIndex = this.generateBlindIndex(action);
    const encryptedPayload = await this.encryptPayload(enrichedPayload);

    try {
      const res = await fetch(`${this.endpoint}/v1/log`, {
        method: "POST",
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ actorBlindIndex, actionBlindIndex, encryptedPayload }),
      });

      return res.ok;
    } catch (err: any) {
      console.error(`[Volidator] Failed to send log: ${err.message}`);
      return false;
    }
  }

  // ---------------------------------------------------------------------------
  // generateEmbedToken() — Sign a HS256 JWT for the embeddable dashboard widget
  // ---------------------------------------------------------------------------
  // Requires projectId and clientSecret in the constructor config.
  // The returned embedUrl can be dropped directly into an <iframe src="...">.
  async generateEmbedToken(config: EmbedTokenConfig): Promise<EmbedTokenResult> {
    if (!this.projectId || !this.clientSecret) {
      throw new Error(
        "generateEmbedToken() requires projectId and clientSecret in the VolidatorClient constructor."
      );
    }

    const {
      actorId,
      expiresIn = "2h",
      dashboardUrl = "https://dash.volidator.com",
    } = config;

    // 1. Compute the blind index for this actor (same HMAC the SDK uses during ingestion)
    const actorBlindIndex = this.generateBlindIndex(actorId);

    // 2. Resolve expiry to seconds
    const expiresInSeconds = this.parseExpiry(expiresIn);
    const now = Math.floor(Date.now() / 1000);

    // 3. Build the JWT payload
    const payload = {
      pid: this.projectId,
      abi: actorBlindIndex,
      iat: now,
      exp: now + expiresInSeconds,
    };

    // 4. Sign as HS256 JWT using the project's clientSecret (matches jose.jwtVerify on the server)
    const token = this.signHS256JWT(payload, this.clientSecret);

    // 5. Append the encryptionKey as the URL hash fragment — browsers never send it to the server
    const embedUrl = `${dashboardUrl}/embed/${token}#${this.encryptionKey}`;

    return { token, embedUrl };
  }

  // ---------------------------------------------------------------------------
  // Private: manual HS256 JWT signing (no external dependency)
  // Produces output identical to jose.SignJWT(...).sign(key) with HS256
  // ---------------------------------------------------------------------------
  private signHS256JWT(payload: object, secret: string): string {
    const header = { alg: "HS256", typ: "JWT" };

    const encode = (obj: object) =>
      Buffer.from(JSON.stringify(obj))
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=/g, "");

    const unsigned = `${encode(header)}.${encode(payload)}`;

    const signature = createHmac("sha256", secret)
      .update(unsigned)
      .digest("base64")
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=/g, "");

    return `${unsigned}.${signature}`;
  }

  // ---------------------------------------------------------------------------
  // Private: parse duration strings like "30m", "2h", "7d" into seconds
  // ---------------------------------------------------------------------------
  private parseExpiry(expiry: string): number {
    const match = expiry.match(/^(\d+)(s|m|h|d)$/);
    if (!match) return 7200; // fallback: 2 hours
    const [, num, unit] = match;
    const n = parseInt(num, 10);
    switch (unit) {
      case "s": return n;
      case "m": return n * 60;
      case "h": return n * 3600;
      case "d": return n * 86400;
      default:  return 7200;
    }
  }
}
