import { createHmac, createHash, createCipheriv, randomBytes } from "crypto";

interface LogPayload {
  actor: string;
  action: string;
  target: string;
  metadata?: Record<string, any>;
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

  // Optional fields required only for generateEmbedToken()
  private projectId?: string;
  private clientSecret?: string;

  constructor(config: {
    apiKey: string;
    encryptionKey: string;
    endpoint?: string;
    // Provide these when you need to generate embed tokens server-side
    projectId?: string;
    clientSecret?: string;
  }) {
    this.apiKey = config.apiKey;
    this.encryptionKey = config.encryptionKey;
    this.endpoint = config.endpoint || "https://ingestion.volidator.com";
    this.projectId = config.projectId;
    this.clientSecret = config.clientSecret;
    // Derive a 256-bit key from the client encryption key (matches SDK & browser WebCrypto)
    this.hashedKey = createHash("sha256").update(config.encryptionKey).digest();
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
  private async encryptPayload(payload: LogPayload): Promise<string> {
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
    const actorBlindIndex = this.generateBlindIndex(payload.actor);
    const actionBlindIndex = this.generateBlindIndex(payload.action);
    const encryptedPayload = await this.encryptPayload(payload);

    const res = await fetch(`${this.endpoint}/v1/log`, {
      method: "POST",
      headers: {
        Authorization: `Bearer ${this.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ actorBlindIndex, actionBlindIndex, encryptedPayload }),
    });

    return res.ok;
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
