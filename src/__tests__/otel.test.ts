import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { trace, context } from "@opentelemetry/api";
import { BasicTracerProvider, SimpleSpanProcessor } from "@opentelemetry/sdk-trace-base";
import { LoggerProvider, SimpleLogRecordProcessor } from "@opentelemetry/sdk-logs";
import { AsyncHooksContextManager } from "@opentelemetry/context-async-hooks";
import { VolidatorClient } from "../index";
import {
  enrichWithOtel,
  enableOtelDriverRedirect,
  VolidatorSpanExporter,
  VolidatorLogExporter,
} from "../plugins/otel";

const TEST_KEY = "volidator-test-key-32-chars-xyzw";

function makeFetchSpy() {
  let lastUrl: string | null = null;
  let lastOpts: RequestInit | undefined = undefined;
  const spy = vi.fn(async (url: string, opts?: RequestInit) => {
    lastUrl = url;
    lastOpts = opts;
    return { ok: true, json: async () => ({ accepted: 1 }) } as Response;
  });
  return { spy, getLastUrl: () => lastUrl, getLastOpts: () => lastOpts };
}

async function decryptPayload(encrypted: string, rawKey: string): Promise<any> {
  const b64 = encrypted.slice(encrypted.indexOf(":") + 1);
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const iv = bytes.slice(0, 12);
  const ciphertext = bytes.slice(12);
  const keyHash = await globalThis.crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(rawKey),
  );
  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    keyHash,
    { name: "AES-GCM" },
    false,
    ["decrypt"],
  );
  const plain = await globalThis.crypto.subtle.decrypt(
    { name: "AES-GCM", iv },
    cryptoKey,
    ciphertext,
  );
  return JSON.parse(new TextDecoder().decode(plain));
}

describe("OpenTelemetry Exporter Plugin", () => {
  let fetchSpy: ReturnType<typeof makeFetchSpy>;
  let client: VolidatorClient;
  let provider: BasicTracerProvider;

  beforeEach(() => {
    fetchSpy = makeFetchSpy();
    vi.stubGlobal("fetch", fetchSpy.spy);

    client = new VolidatorClient({
      projectId: "prj_test_123",
      apiKey: "val_live_test_key",
      encryptionKey: TEST_KEY,
      endpoint: "http://localhost:8787",
      referenceKeys: ["actor", "target", "tenant"],
    });

    // Setup and enable context manager for async boundary tracing
    const contextManager = new AsyncHooksContextManager();
    contextManager.enable();
    context.setGlobalContextManager(contextManager);

    // Register active OTel tracer provider
    provider = new BasicTracerProvider();
    provider.register();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    // Reset global context manager and tracer provider to avoid test pollution
    context.disable();
    trace.disable();
  });

  it("enrichWithOtel extracts active trace details correctly", async () => {
    const tracer = trace.getTracer("test-tracer");
    await tracer.startActiveSpan("my-active-span", async (span) => {
      try {
        const payload = enrichWithOtel({
          action: "test.action",
        });

        expect(payload.traceId).toBe(span.spanContext().traceId);
        expect(payload.spanId).toBe(span.spanContext().spanId);
      } finally {
        span.end();
      }
    });
  });

  it("prepareLogEntry resolves active trace details automatically if not provided", async () => {
    const tracer = trace.getTracer("test-tracer");
    await tracer.startActiveSpan("my-active-span-auto", async (span) => {
      try {
        const entry = await (client as any).prepareLogEntry({
          action: "test.action",
          actor: "usr_alice",
        });

        // The returned encrypted entry or payload inside it should carry trace/span context
        const parsedEntry = await decryptPayload(entry.encryptedPayload, TEST_KEY);
        const expectedTraceBlindIndex = await (client as any).generateBlindIndex(
          span.spanContext().traceId,
          await (client as any)._getHashedKey((client as any).activeKeyId),
        );
        expect(entry.traceBlindIndex).toBe(expectedTraceBlindIndex);
        expect(parsedEntry.spanId).toBe(span.spanContext().spanId);
      } finally {
        span.end();
      }
    });
  });

  it("enableOtelDriverRedirect intercepts client.log() and adds span event", async () => {
    // 1. Setup redirect
    enableOtelDriverRedirect(client);

    // 2. Setup standard exporter spy to capture the span ends
    const customExporterSpy = vi.fn();
    const exporter = {
      export: (spans: any[], callback: any) => {
        customExporterSpy(spans);
        callback({ code: 0 });
      },
      shutdown: async () => {},
    };
    provider.addSpanProcessor(new SimpleSpanProcessor(exporter));

    const tracer = trace.getTracer("test-tracer");
    await tracer.startActiveSpan("redirect-span", async (span) => {
      try {
        // This should not hit direct HTTP ingestion
        const status = await client.log({
          action: "redirected.action",
          actor: "usr_bob",
        });

        expect(status).toBe(true);
        expect(fetchSpy.spy).not.toHaveBeenCalled();
      } finally {
        span.end();
      }
    });

    expect(customExporterSpy).toHaveBeenCalledTimes(1);
    const completedSpan = customExporterSpy.mock.calls[0][0][0];
    expect(completedSpan.events).toHaveLength(1);
    expect(completedSpan.events[0].name).toBe("volidator.audit");
    expect(completedSpan.events[0].attributes["volidator.payload"]).toContain("redirected.action");
  });

  it("VolidatorSpanExporter forwards redirected span events to Volidator endpoint", async () => {
    const volidatorExporter = new VolidatorSpanExporter(client);
    provider.addSpanProcessor(new SimpleSpanProcessor(volidatorExporter));

    const tracer = trace.getTracer("test-tracer");
    await tracer.startActiveSpan("export-span", async (span) => {
      try {
        span.addEvent("volidator.audit", {
          "volidator.payload": JSON.stringify({
            action: "exported.action",
            actor: "usr_charlie",
          }),
        });
      } finally {
        span.end();
      }
    });

    // The exporter executes asynchronously in the SimpleSpanProcessor callback chain.
    // Allow the microtask queue to clear.
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(fetchSpy.spy).toHaveBeenCalledTimes(1);
    expect(fetchSpy.getLastUrl()).toBe("http://localhost:8787/v1/log");
  });

  it("VolidatorSpanExporter maps generic spans with compliance attributes automatically", async () => {
    const volidatorExporter = new VolidatorSpanExporter(client);
    provider.addSpanProcessor(new SimpleSpanProcessor(volidatorExporter));

    const tracer = trace.getTracer("test-tracer");
    await tracer.startActiveSpan("generic-span", async (span) => {
      try {
        span.setAttribute("volidator.action", "generic.action");
        span.setAttribute("volidator.actor", "usr_diana");
        span.setAttribute("volidator.target", "file_abc");
      } finally {
        span.end();
      }
    });

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(fetchSpy.spy).toHaveBeenCalledTimes(1);
    const bodyObj = JSON.parse(fetchSpy.getLastOpts()?.body as string);
    const decrypted = await decryptPayload(bodyObj.encryptedPayload, TEST_KEY);

    expect(decrypted.action).toBe("generic.action");
    expect(decrypted.actor).toBe("[REF:usr_diana]"); // reference keys
    expect(decrypted.target).toBe("[REF:file_abc]");
  });

  it("VolidatorLogExporter maps log records correctly", async () => {
    const volidatorLogExporter = new VolidatorLogExporter(client);
    const loggerProvider = new LoggerProvider();
    loggerProvider.addLogRecordProcessor(new SimpleLogRecordProcessor(volidatorLogExporter));
    const logger = loggerProvider.getLogger("test-logger");

    logger.emit({
      body: "compliance-event",
      attributes: {
        "volidator.action": "log.action",
        "volidator.actor": "usr_evan",
      },
    });

    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(fetchSpy.spy).toHaveBeenCalledTimes(1);
    const bodyObj = JSON.parse(fetchSpy.getLastOpts()?.body as string);
    const decrypted = await decryptPayload(bodyObj.encryptedPayload, TEST_KEY);

    expect(decrypted.action).toBe("log.action");
    expect(decrypted.actor).toBe("[REF:usr_evan]");
  });
});
