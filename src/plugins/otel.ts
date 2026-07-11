import { trace } from "@opentelemetry/api";
import {
  type SpanExporter,
  type ReadableSpan,
} from "@opentelemetry/sdk-trace-base";
import {
  type ExportResult,
  ExportResultCode,
} from "@opentelemetry/core";
import { type LogRecordExporter, type ReadableLogRecord } from "@opentelemetry/sdk-logs";
import { type LogPayload, VolidatorClient } from "../index";

// Auto-register resolver when OTel plugin is imported
VolidatorClient.otelContextResolver = () => {
  try {
    const activeSpan = trace.getActiveSpan();
    if (activeSpan) {
      const spanContext = activeSpan.spanContext();
      return {
        traceId: spanContext.traceId,
        spanId: spanContext.spanId,
      };
    }
  } catch {}
  return null;
};

/**
 * Enrich a Volidator log payload with current OpenTelemetry active span details.
 * Maps the active span's traceId, spanId, and parentSpanId automatically.
 */
export function enrichWithOtel(payload: LogPayload): LogPayload {
  try {
    const activeSpan = trace.getActiveSpan();
    if (activeSpan) {
      const spanContext = activeSpan.spanContext();
      const enriched = { ...payload };

      if (!enriched.traceId) {
        enriched.traceId = spanContext.traceId;
      }
      if (!enriched.spanId) {
        enriched.spanId = spanContext.spanId;
      }
      if (!enriched.parentSpanId && (activeSpan as any).parentSpanId) {
        enriched.parentSpanId = (activeSpan as any).parentSpanId;
      }

      return enriched;
    }
  } catch (e) {
    console.warn("[Volidator] Failed to enrich log payload with OpenTelemetry context", e);
  }
  return payload;
}

/**
 * Enables Client-side OpenTelemetry Driver Redirect.
 * Intercepts all client.log() calls, emitting them as OpenTelemetry Span events
 * on the active span instead of performing direct HTTP logging.
 */
export function enableOtelDriverRedirect(client: VolidatorClient): void {
  // If already redirected, do not wrap again
  if ((client as any)._originalLog) {
    return;
  }

  const originalLog = client.log.bind(client);
  (client as any)._originalLog = originalLog;

  client.log = async (payload: LogPayload, maxMetaOverride?: number) => {
    // Loop prevention check
    if (payload.metadata?.__volidator_internal_otel_routed) {
      const cleanedMetadata = { ...payload.metadata };
      delete cleanedMetadata.__volidator_internal_otel_routed;
      return originalLog({ ...payload, metadata: cleanedMetadata }, maxMetaOverride);
    }

    try {
      const activeSpan = trace.getActiveSpan();
      if (activeSpan) {
        activeSpan.addEvent("volidator.audit", {
          "volidator.payload": JSON.stringify(payload),
        });
        return true;
      }
    } catch (err) {
      console.warn(
        "[Volidator] Failed to redirect audit event to OpenTelemetry, falling back to direct ingestion",
        err,
      );
    }

    // Fall back to direct HTTP delivery if no active span or OTel fails
    return originalLog(payload, maxMetaOverride);
  };
}

/**
 * An OpenTelemetry Span Exporter that captures Volidator events or annotated
 * span compliance contexts and forwards them securely to Volidator.
 */
export class VolidatorSpanExporter implements SpanExporter {
  private originalLog: any;

  constructor(client: VolidatorClient) {
    this.originalLog = (client as any)._originalLog || client.log.bind(client);
  }

  export(spans: ReadableSpan[], resultCallback: (result: ExportResult) => void): void {
    const promises: Promise<boolean>[] = [];

    for (const span of spans) {
      const spanContext = span.spanContext();
      const attributes = span.attributes || {};

      // 1. Process explicit volidator.audit span event redirects first
      let redirected = false;
      for (const event of span.events) {
        if (event.name === "volidator.audit") {
          const payloadStr = event.attributes?.["volidator.payload"];
          if (typeof payloadStr === "string") {
            try {
              const payload = JSON.parse(payloadStr) as LogPayload;
              const metadata = {
                ...payload.metadata,
                __volidator_internal_otel_routed: true,
              };
              promises.push(this.originalLog({ ...payload, metadata }));
              redirected = true;
            } catch (err) {
              console.error("[Volidator] Failed to parse redirected audit event from span", err);
            }
          }
        }
      }

      if (redirected) {
        continue;
      }

      // 2. Map generic trace spans that explicitly flag compliance metadata
      const action = attributes["volidator.action"] || attributes["audit.action"];
      if (action && typeof action === "string") {
        const actor = attributes["volidator.actor"] || attributes["audit.actor"];
        const target = attributes["volidator.target"] || attributes["audit.target"];
        const tenant = attributes["volidator.tenant"] || attributes["audit.tenant"];

        const payload: LogPayload = {
          action,
          actor: (actor || "unknown") as string,
          target: target as string,
          tenant: tenant as string,
          traceId: spanContext.traceId,
          spanId: spanContext.spanId,
          parentSpanId: span.parentSpanId,
          metadata: {
            ...attributes,
          },
        };

        promises.push(
          this.originalLog({
            ...payload,
            metadata: {
              ...payload.metadata,
              __volidator_internal_otel_routed: true,
            },
          }),
        );
      }
    }

    if (promises.length === 0) {
      resultCallback({ code: ExportResultCode.SUCCESS });
      return;
    }

    Promise.all(promises)
      .then(() => {
        resultCallback({ code: ExportResultCode.SUCCESS });
      })
      .catch((err) => {
        resultCallback({
          code: ExportResultCode.FAILED,
          error: err instanceof Error ? err : new Error(String(err)),
        });
      });
  }

  async shutdown(): Promise<void> {
    // No-op
  }
}

/**
 * An OpenTelemetry Log Record Exporter that processes generic and explicit
 * log event records and forwards them to Volidator.
 */
export class VolidatorLogExporter implements LogRecordExporter {
  private originalLog: any;

  constructor(client: VolidatorClient) {
    this.originalLog = (client as any)._originalLog || client.log.bind(client);
  }

  export(logs: ReadableLogRecord[], resultCallback: (result: ExportResult) => void): void {
    const promises: Promise<boolean>[] = [];

    for (const logRecord of logs) {
      const attributes = logRecord.attributes || {};
      const payloadStr = attributes["volidator.payload"];

      // 1. Process explicit redirects
      if (typeof payloadStr === "string") {
        try {
          const payload = JSON.parse(payloadStr) as LogPayload;
          const metadata = {
            ...payload.metadata,
            __volidator_internal_otel_routed: true,
          };
          promises.push(this.originalLog({ ...payload, metadata }));
          continue;
        } catch (err) {
          console.error("[Volidator] Failed to parse redirected audit event from log record", err);
        }
      }

      // 2. Map generic log entries carrying compliance fields
      const action = attributes["volidator.action"] || attributes["audit.action"];
      if (action && typeof action === "string") {
        const actor = attributes["volidator.actor"] || attributes["audit.actor"];
        const target = attributes["volidator.target"] || attributes["audit.target"];
        const tenant = attributes["volidator.tenant"] || attributes["audit.tenant"];
        const spanContext = logRecord.spanContext;

        const payload: LogPayload = {
          action,
          actor: (actor || "unknown") as string,
          target: target as string,
          tenant: tenant as string,
          traceId: spanContext?.traceId,
          spanId: spanContext?.spanId,
          metadata: {
            ...attributes,
            body: logRecord.body,
          },
        };

        promises.push(
          this.originalLog({
            ...payload,
            metadata: {
              ...payload.metadata,
              __volidator_internal_otel_routed: true,
            },
          }),
        );
      }
    }

    if (promises.length === 0) {
      resultCallback({ code: ExportResultCode.SUCCESS });
      return;
    }

    Promise.all(promises)
      .then(() => {
        resultCallback({ code: ExportResultCode.SUCCESS });
      })
      .catch((err) => {
        resultCallback({
          code: ExportResultCode.FAILED,
          error: err instanceof Error ? err : new Error(String(err)),
        });
      });
  }

  async shutdown(): Promise<void> {
    // No-op
  }
}
