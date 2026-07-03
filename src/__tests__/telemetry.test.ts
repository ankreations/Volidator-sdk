/**
 * Telemetry configuration & context extraction — unit tests
 *
 * Tests: resolveTelemetryConfig (via private static), extractContext (public static)
 */

import { describe, it, expect } from "vitest";
import { VolidatorClient, TelemetryConfig } from "../index";

// ---------------------------------------------------------------------------
// resolveTelemetryConfig (accessed via private static cast)
// ---------------------------------------------------------------------------

function resolve(config: TelemetryConfig) {
  return (VolidatorClient as any).resolveTelemetryConfig(config);
}

describe("resolveTelemetryConfig — presets", () => {
  it("strict preset → ip:skip, userAgent:skip, location:false", () => {
    expect(resolve({ preset: "strict" })).toEqual({
      ip: "skip",
      userAgent: "skip",
      location: false,
    });
  });

  it("standard preset → ip:anonymize, userAgent:parse, location:true", () => {
    expect(resolve({ preset: "standard" })).toEqual({
      ip: "anonymize",
      userAgent: "parse",
      location: true,
    });
  });

  it("full preset → ip:track, userAgent:track, location:true", () => {
    expect(resolve({ preset: "full" })).toEqual({
      ip: "track",
      userAgent: "track",
      location: true,
    });
  });

  it("defaults to standard when no preset is provided", () => {
    expect(resolve({})).toEqual({
      ip: "anonymize",
      userAgent: "parse",
      location: true,
    });
  });
});

describe("resolveTelemetryConfig — per-field overrides", () => {
  it("overrides ip on top of a preset", () => {
    const result = resolve({ preset: "strict", ip: "anonymize" });
    expect(result.ip).toBe("anonymize");
    expect(result.userAgent).toBe("skip"); // strict baseline
  });

  it("overrides userAgent on top of a preset", () => {
    const result = resolve({ preset: "full", userAgent: "skip" });
    expect(result.userAgent).toBe("skip");
    expect(result.ip).toBe("track"); // full baseline
  });

  it("overrides location on top of a preset", () => {
    const result = resolve({ preset: "full", location: false });
    expect(result.location).toBe(false);
  });

  it("applies all three overrides simultaneously", () => {
    const result = resolve({
      preset: "strict",
      ip: "track",
      userAgent: "parse",
      location: true,
    });
    expect(result).toEqual({ ip: "track", userAgent: "parse", location: true });
  });
});

// ---------------------------------------------------------------------------
// extractContext — Cloudflare Workers headers
// ---------------------------------------------------------------------------

describe("extractContext — Cloudflare Workers headers", () => {
  function makeCfRequest(headers: Record<string, string>) {
    return {
      headers: {
        get: (name: string) => headers[name] ?? headers[name.toLowerCase()] ?? null,
      },
    };
  }

  it("extracts IP from cf-connecting-ip", () => {
    const ctx = VolidatorClient.extractContext(
      makeCfRequest({ "cf-connecting-ip": "1.2.3.4" })
    );
    expect(ctx.ip).toBe("1.2.3.4");
  });

  it("falls back to x-real-ip if cf-connecting-ip is absent", () => {
    const ctx = VolidatorClient.extractContext(
      makeCfRequest({ "x-real-ip": "5.6.7.8" })
    );
    expect(ctx.ip).toBe("5.6.7.8");
  });

  it("falls back to x-forwarded-for and takes first IP", () => {
    const ctx = VolidatorClient.extractContext(
      makeCfRequest({ "x-forwarded-for": "9.10.11.12, 13.14.15.16" })
    );
    expect(ctx.ip).toBe("9.10.11.12");
  });

  it("extracts country from cf-ipcountry", () => {
    const ctx = VolidatorClient.extractContext(
      makeCfRequest({ "cf-connecting-ip": "1.2.3.4", "cf-ipcountry": "US" })
    );
    expect(ctx.location?.country).toBe("US");
  });

  it("extracts region from cf-region-code", () => {
    const ctx = VolidatorClient.extractContext(
      makeCfRequest({ "cf-connecting-ip": "1.2.3.4", "cf-region-code": "CA" })
    );
    expect(ctx.location?.region).toBe("CA");
  });

  it("extracts city from cf-ipcity", () => {
    const ctx = VolidatorClient.extractContext(
      makeCfRequest({ "cf-connecting-ip": "1.2.3.4", "cf-ipcity": "San Francisco" })
    );
    expect(ctx.location?.city).toBe("San Francisco");
  });

  it("extracts User-Agent header", () => {
    const ctx = VolidatorClient.extractContext(
      makeCfRequest({ "user-agent": "Mozilla/5.0 Chrome/124" })
    );
    expect(ctx.userAgent).toBe("Mozilla/5.0 Chrome/124");
  });
});

// ---------------------------------------------------------------------------
// extractContext — Vercel / generic proxy headers
// ---------------------------------------------------------------------------

describe("extractContext — Vercel headers", () => {
  function makeCfRequest(headers: Record<string, string>) {
    return {
      headers: {
        get: (name: string) => headers[name] ?? null,
      },
    };
  }

  it("extracts country from x-vercel-ip-country", () => {
    const ctx = VolidatorClient.extractContext(
      makeCfRequest({ "x-vercel-ip-country": "DE" })
    );
    expect(ctx.location?.country).toBe("DE");
  });

  it("extracts region from x-vercel-ip-country-region", () => {
    const ctx = VolidatorClient.extractContext(
      makeCfRequest({ "x-vercel-ip-country-region": "BY" })
    );
    expect(ctx.location?.region).toBe("BY");
  });
});

// ---------------------------------------------------------------------------
// extractContext — Node.js IncomingMessage style headers
// ---------------------------------------------------------------------------

describe("extractContext — Node.js IncomingMessage headers", () => {
  it("reads headers from a plain object (Node HTTP style)", () => {
    const req = {
      headers: {
        "cf-connecting-ip": "10.0.0.1",
        "user-agent": "Node/20",
        "cf-ipcountry": "IN",
      },
    };
    const ctx = VolidatorClient.extractContext(req);
    expect(ctx.ip).toBe("10.0.0.1");
    expect(ctx.userAgent).toBe("Node/20");
    expect(ctx.location?.country).toBe("IN");
  });

  it("handles a null/undefined request gracefully", () => {
    const ctx = VolidatorClient.extractContext(null);
    expect(ctx.ip).toBe("");
    expect(ctx.userAgent).toBe("");
  });
});
