# Volidator Node.js SDK

**Zero-knowledge, server-blind audit logging for Node.js, Next.js, and edge runtimes.**

Volidator encrypts every log entry locally — on your server — before sending it. The Volidator backend stores only ciphertext and blind indexes. Your plaintext data never leaves your infrastructure unencrypted.

[![npm](https://img.shields.io/npm/v/@volidator/node)](https://www.npmjs.com/package/@volidator/node)
[![license](https://img.shields.io/npm/l/@volidator/node)](LICENSE)

**[Website & Sign Up](https://volidator.com) | [Developer Documentation](https://docs.volidator.com)**

---

## What is Volidator?

**Volidator** is the developer-first, zero-knowledge audit log infrastructure built for modern applications, enterprise B2B SaaS, and autonomous AI agents. By utilizing local AES-256-GCM encryption and blind indexing (HMAC-SHA-256) on your servers before ingestion, Volidator allows you to store, query, and stream audit trails without ever holding or exposing raw PII (Personally Identifiable Information) or sensitive activity data (though configurable if you want to host PII/PHI with us).

---

## Why Volidator? (Pain Points We Solve)

Traditional logging tools force a dangerous compromise: either send raw customer data to a third-party logging vendor (creating security liabilities, compliance issues, and API keys leakage risks), or spend months building a custom, secure compliance database in-house.

Volidator solves this with **Zero-Knowledge Audit Trails**:
* **Enterprise Compliance in Minutes:** Unlocks enterprise-ready audit logging matching SOC 2 (CC6.x), ISO 27001 (A.12.4), HIPAA, and GDPR standards under 5 minutes.
* **Zero Trust Security:** Even if Volidator's databases were compromised, hackers see only randomized ciphertext. Decryption keys live exclusively in your server environment variables and the user's browser hash fragments.
* **AI Agent Action Auditing & Accountability:** Autonomous AI agents make decisions, run API calls, and modify databases. Volidator provides a tamper-proof ledger to trace exactly *which* agent tool was executed, *why* (LLM prompt/context), and *what* was modified, satisfying critical alignment and security monitoring requirements.
* **Instant Customer-Facing Dashboards:** Embed fully-interactive, securely hydrated log tables inside your React frontends using our signed JIT tokens.

---

## Who is it for?

* **B2B SaaS Engineering Teams:** Developers who need to provide enterprise tenants with search, filter, and CSV exports of system events.
* **Security & Compliance Teams:** Organizations aiming to achieve security certifications without expanding their data privacy liability or telemetry footprint.
* **AI & Agentic App Developers:** Builders establishing guardrails and debug logs for autonomous systems to audit agent decisions, LLM outputs, and automated tool calls.

---

## Table of Contents

1. [Install](#1-install)
2. [Environment Setup](#2-environment-setup)
3. [Initialize the Client](#3-initialize-the-client)
4. [Log an Event](#4-log-an-event)
5. [Pass Request Context](#5-pass-request-context)
6. [Telemetry Configuration](#6-telemetry-configuration)
7. [PII Redaction](#7-pii-redaction)
8. [JIT Hydration (referenceKeys)](#8-jit-hydration-referencekeys)
9. [Keyring Rotation](#9-keyring-rotation)
10. [Embed Token](#10-embed-token)
11. [Compliance Helpers](#11-compliance-helpers)
12. [Next.js Middleware](#12-nextjs-middleware)
14. [`@volidator/react`](#14-volidatorreact)
15. [AI Agent Auditing (VolidatorAgent)](#15-ai-agent-auditing-volidatoragent)
16. [Batch Ingestion (logBatch)](#16-batch-ingestion-logbatch)
17. [Large Payloads (Claim Check Pattern)](#17-large-payloads-claim-check-pattern)

---

## 1. Install

```bash
npm install @volidator/node
```

---

## 2. Environment Setup

Generate a secure 32-byte encryption key (64 hex characters) with the `vol-dek-` prefix:
```bash
node -e "const b=require('crypto').randomBytes(32);console.log('vol-dek-'+b.toString('hex'))"
```

Then add it as an environment secret:
```bash
# Authenticates your server with the Volidator ingestion endpoint
VOLIDATOR_API_KEY="val_live_xxxxxxxx..."

# AES-256-GCM encryption key — your data is encrypted with this before leaving your server
VOLIDATOR_ENCRYPTION_KEY="vol-dek-xxxxxxxx..."
```

---

## 3. Initialize the Client

Create **one instance** per application and reuse it. Do not instantiate per-request.

```typescript
import { VolidatorClient } from "@volidator/node";

export const volidator = new VolidatorClient({
  apiKey: process.env.VOLIDATOR_API_KEY!,
  encryptionKey: process.env.VOLIDATOR_ENCRYPTION_KEY!,
  
  // Optional configuration for delivery retries and sizes:
  maxRetries: 3,         // Retry up to 3 times on transient errors (default: 3)
  maxMetadataSize: 10240, // Cap serialized metadata size at 10KB (default: 10KB)
  
  onDeliveryFailure: (payload, error) => {
    // Callback invoked when a log permanently fails to deliver after all retries
    console.error(`Log delivery failed permanently for action "${payload.action}": ${error.message}`);
  }
});
```

### Transient Errors & Retry Strategy
By default, the SDK automatically retries log delivery on network errors or 5xx server responses using an exponential backoff strategy (delays: ~500ms → ~1500ms → ~4500ms). Client errors (4xx) are never retried.

> **⚠️ Serverless / Edge Function execution time caveat:**
> Worst-case retry attempts take up to ~6.5 seconds. If you are running inside a serverless or Edge environment (e.g. Vercel, Next.js Edge, Cloudflare Workers) with strict duration limits:
> - Wrap log calls in `ctx.waitUntil(volidator.log(...))` so the worker doesn't block response delivery.
> - Or reduce `maxRetries` to `1` (or `0` to disable retries) to avoid hitting runtime execution limits.

### Metadata Limits & Truncation
Log metadata is subject to a hard depth limit of **5 levels** and string value length limit of **1000 characters**. In non-production environments (`NODE_ENV !== 'production'`), the SDK will emit warnings in the console if any metadata is truncated.

---

## 4. Log an Event

```typescript
await volidator.log({
  actor: "usr_12345",              // Who performed the action
  action: "user.login.success",   // What happened (use dot notation)
  target: "workspace_abc789",     // What was affected
  metadata: {
    deviceName: "MacBook Pro",
    authProvider: "Google OAuth",
  },
});
```

`log()` returns `true` if the event was accepted, `false` if delivery failed. It never throws — failures are swallowed and logged to `console.error`.

---

## 5. Pass Request Context

Pass your framework's `Request` object directly. The SDK extracts IP, User-Agent, and geolocation headers automatically.

```typescript
// Next.js App Router / Cloudflare Workers / Express
await volidator.log({
  actor: session.userId,
  action: "settings.update",
  req: request,  // Web API Request or Node.js IncomingMessage
  metadata: { fieldChanged: "email_address" },
});
```

Supported request formats:
- `Request` — Next.js App Router, Cloudflare Workers, Bun
- `IncomingMessage` — Node.js `http`, Express, Fastify

---

## 6. Telemetry Configuration

Control how IP, User-Agent, and location data are handled. Choose a preset, then override individual fields as needed.

| Preset | IP | User-Agent | Location |
|---|---|---|---|
| `"strict"` | skip | skip | disabled |
| `"standard"` *(default)* | anonymized (hashed) | parsed to browser/OS | country + region |
| `"full"` | stored as-is | stored as-is | country + region + city |

```typescript
const volidator = new VolidatorClient({
  apiKey: process.env.VOLIDATOR_API_KEY!,
  encryptionKey: process.env.VOLIDATOR_ENCRYPTION_KEY!,
  telemetry: {
    preset: "standard",      // baseline
    ip: "skip",              // override: don't store IP at all
    location: false,         // override: disable geolocation
  },
});
```

---

## 7. PII Redaction

For fields containing sensitive data that should never be stored — even in encrypted form — use `redactKeys`. The value is replaced with `[REDACTED:fieldName]` **before** encryption.

```typescript
const volidator = new VolidatorClient({
  apiKey: process.env.VOLIDATOR_API_KEY!,
  encryptionKey: process.env.VOLIDATOR_ENCRYPTION_KEY!,
  redactKeys: ["actor", "metadata.socialSecurityNumber", "metadata.email"],
});
```

Supported key patterns:
- `"actor"` — the top-level actor field
- `"target"` — the top-level target field  
- `"metadata.fieldName"` — any metadata field by name

> **Blind indexes are still computed from the original value before redaction**, so the Volidator dashboard can still filter and search by actor/target even after redaction.

---

## 8. JIT Hydration (`referenceKeys`)

JIT (Just-In-Time) Hydration lets you store a **non-sensitive reference ID** instead of PII, while preserving full dashboard display names. PII never reaches Volidator's servers.

When you configure `referenceKeys`, you pass fields as `{ id, pii }` objects:
- `id` — the internal identifier stored as `[REF:id]` in the encrypted log
- `pii` — the real value used **only** to compute the blind index, then discarded

The dashboard resolves `[REF:id]` to a display name at render time by sending a `postMessage` request back to your application. See the [`@volidator/react`](#14-volidatorreact) section for the client-side hook.

```typescript
const volidator = new VolidatorClient({
  apiKey: process.env.VOLIDATOR_API_KEY!,
  encryptionKey: process.env.VOLIDATOR_ENCRYPTION_KEY!,
  referenceKeys: ["actor"],
});

await volidator.log({
  // Pass { id, pii } for any field in referenceKeys
  actor: { id: "usr_890", pii: "alice@company.com" },
  action: "document.deleted",
  target: "doc_4521",
});
// Stored: actor = "[REF:usr_890]"
// Blind index computed from "alice@company.com" — search still works
```

`referenceKeys` and `redactKeys` can coexist. If a field is in both, `referenceKeys` takes precedence.

→ [Full JIT Hydration guide](https://docs.volidator.com/guides/jit-hydration/)

---

## 9. Keyring Rotation

Rotate your encryption key without re-encrypting historical logs. Provide a `keyring` (all active key versions) and `activeEncryptionKeyId` (the key used for new writes). Old logs are decrypted with whichever key was active when they were written.

```typescript
const volidator = new VolidatorClient({
  apiKey: process.env.VOLIDATOR_API_KEY!,
  keyring: {
    v1: process.env.VOLIDATOR_KEY_V1!,  // old — decrypts historical logs
    v2: process.env.VOLIDATOR_KEY_V2!,  // new — encrypts all new writes
  },
  activeEncryptionKeyId: "v2",
});
```

Constraints:
- Keyring size is capped at **5 keys** (security + performance bound).
- `activeEncryptionKeyId` must be present in the `keyring` object.

---

## 10. Embed Token

Generate a signed JWT that scopes the embeddable dashboard widget to a specific actor, target, or tenant. This is called server-side; the returned `embedUrl` is dropped directly into an `<iframe>`.

```typescript
const volidator = new VolidatorClient({
  apiKey: process.env.VOLIDATOR_API_KEY!,
  encryptionKey: process.env.VOLIDATOR_ENCRYPTION_KEY!,
  // Required for generateEmbedToken():
  projectId: process.env.VOLIDATOR_PROJECT_ID!,
  clientSecret: process.env.VOLIDATOR_CLIENT_SECRET!,
});

const { embedUrl } = await volidator.generateEmbedToken({
  actorId: session.userId,          // Scope to this actor's logs
  scope: "actor",                   // "actor" | "target" | "tenant" | "all" | "auditor"
  expiresIn: "1h",                  // Max: 1h for actor/target/tenant; 7d for auditor
  hostOrigin: "https://app.yourcompany.com",  // Enables strict postMessage origin validation
  view: {
    columns: ["actor", "action", "metadata.ipAddress", "createdAt"],
    defaultFilter: { action: "user.login" },
  },
});

// In your API route response:
return Response.json({ embedUrl });
```

```tsx
// In your React component:
<iframe src={embedUrl} width="100%" height="600" />
```

---

## 11. Compliance Helpers

`volidator.compliance` provides pre-tagged methods for common SOC 2 and ISO 27001 audit events. Each method automatically appends the correct `soc2_control` and `iso27001` keys to the log metadata.

```typescript
// Access provisioning
await volidator.compliance.accessGranted({ actor: "admin_01", target: "usr_890" });
await volidator.compliance.accessRevoked({ actor: "admin_01", target: "usr_890" });

// Data movement
await volidator.compliance.dataExported({
  actor: "usr_123",
  metadata: { exportFormat: "csv", rowCount: 5420 },
});

// System changes
await volidator.compliance.systemConfigChanged({
  actor: "usr_123",
  metadata: { setting: "mfa_enforcement", newValue: "required" },
});

// Authentication
await volidator.compliance.mfaEnabled({ actor: "usr_890" });
```

| Method | Action stored | SOC 2 | ISO 27001 |
|---|---|---|---|
| `accessGranted` | `access.granted` | CC6.1 | A.9.2.1 |
| `accessRevoked` | `access.revoked` | CC6.1 | A.9.2.6 |
| `dataExported` | `data.exported` | CC6.6 | A.12.4.1 |
| `systemConfigChanged` | `system.config_changed` | CC6.2 | A.12.1.2 |
| `mfaEnabled` | `mfa.enabled` | CC6.3 | A.9.4.2 |

---

## 12. Next.js Middleware

The `withVolidator` wrapper injects a request-scoped `volidator` object into every Next.js App Router handler. It automatically extracts IP, User-Agent, and geolocation from the incoming request and merges it into every `log()` and `compliance.*()` call — no manual `req` passing needed.

```typescript
import { withVolidator } from "@volidator/node/next";
import { volidator } from "@/lib/volidator";

export const POST = withVolidator(volidator, async (req: Request, ctx) => {
  await ctx.volidator.log({
    actor: session.userId,
    action: "invoice.created",
    target: invoiceId,
  });

  // Compliance methods also receive full telemetry context:
  await ctx.volidator.compliance.dataExported({ actor: session.userId });

  return Response.json({ ok: true });
});
```

---

## 13. Auth Plugins

Auth plugins extend `withVolidator` to automatically inject the authenticated user's ID as `actor` on every log call.

### Clerk

```typescript
import { createClerkAudit } from "@volidator/node/clerk";
import { auth } from "@clerk/nextjs/server";
import { volidator } from "@/lib/volidator";

const withClerkAudit = createClerkAudit({ client: volidator, getAuth: auth });

export const DELETE = withClerkAudit(async (req: Request, ctx) => {
  // ctx.session — Clerk session object
  // actor is automatically set to ctx.session.userId
  await ctx.volidator.log({ action: "record.deleted", target: recordId });
  return Response.json({ ok: true });
});
```

### Universal (Auth0, NextAuth, BetterAuth, Kinde, Supabase, ...)

```typescript
import { createUniversalAudit } from "@volidator/node/universal";
import { getServerSession } from "next-auth";
import { volidator } from "@/lib/volidator";

const withAudit = createUniversalAudit({
  client: volidator,
  getSession: (req) => getServerSession(),
  getUserId: (req, session) => session?.user?.id,
  // Optionally inject extra metadata into every log call:
  getMetadata: (req, session) => ({ userEmail: session?.user?.email }),
});

export const PUT = withAudit(async (req: Request, ctx) => {
  await ctx.volidator.log({ action: "profile.updated" });
  return Response.json({ ok: true });
});
```

---

## 14. `@volidator/react`

The `@volidator/react` package provides the `useVolidatorHydration` hook, which manages the JIT Hydration postMessage handshake between your application and the Volidator embed iframe.

```bash
npm install @volidator/react
```

```tsx
import { useRef } from "react";
import { useVolidatorHydration } from "@volidator/react";

export function AuditLogPage({ embedUrl }: { embedUrl: string }) {
  const iframeRef = useRef<HTMLIFrameElement>(null);

  useVolidatorHydration({
    iframeRef,
    volidatorOrigin: "https://dash.volidator.com",
    resolveActors: async (ids) => {
      // Called with a deduplicated batch of reference IDs from decrypted logs.
      // Return a map of id → { name, avatarUrl? }.
      const res = await fetch("/api/users/resolve", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ids }),
      });
      return res.json();
    },
  });

  return <iframe ref={iframeRef} src={embedUrl} width="100%" height="600" />;
}
```

The hook:
1. Listens for `VOLIDATOR_RESOLVE_ACTORS` messages from the iframe.
2. Validates `event.origin` strictly against `volidatorOrigin` (wildcard `"*"` is not accepted).
3. Calls `resolveActors(ids)` with only the IDs not already in the local cache.
4. Posts the resolution map back into the iframe as `VOLIDATOR_RESOLVE_RESPONSE`.
5. Cleans up the event listener on component unmount.

→ [Full JIT Hydration guide](https://docs.volidator.com/guides/jit-hydration/)

---

## 15. AI Agent Auditing (`VolidatorAgent`)

Volidator provides a specialized compliance logging namespace tailored for autonomous AI systems, LLMs, and multi-agent chains. Access these methods via `volidator.agent.*`.

Every call automatically appends the correct mapping metadata for **EU AI Act compliance**, **NIST AI RMF guidelines**, **SOC 2**, and **ISO 27001**.

```typescript
// 1. Log an agent tool call or external API request
await volidator.agent.toolCall({
  actor: "writer-agent-v1",
  traceId: runId,
  spanId: spanId,
  toolName: "fetch_news",
  toolInput: { topic: "AI Act updates" },
  toolOutput: { results: ["..." ] },
  success: true,
  latencyMs: 140,
});

// 2. Log an autonomous decision made by the model
await volidator.agent.decision({
  actor: "writer-agent-v1",
  traceId: runId,
  decision: "publish_article",
  rationale: "article scoring passed verification checks",
  confidenceScore: 0.96,
  modelId: "claude-3-5-sonnet",
});

// 3. Request human oversight/escalation (EU AI Act Article 14)
await volidator.agent.escalation({
  actor: "writer-agent-v1",
  traceId: runId,
  reason: "article output score fell below threshold",
  urgency: "medium",
  blockedAction: "auto_publish",
});

// 4. Log suspected anomalies, injections, or system security events
await volidator.agent.anomaly({
  actor: "guardrail-shield",
  traceId: runId,
  description: "jailbreak prompt pattern detected in input stream",
  severity: "critical",
  anomalyType: "prompt_injection",
});

// 5. Log a model refusal based on safety alignment rules
await volidator.agent.refusal({
  actor: "writer-agent-v1",
  traceId: runId,
  refusedInstruction: "write code to extract system logs",
  reason: "corporate security policy alignment violation",
});

// 6. Log execution context handoffs in multi-agent workflows
await volidator.agent.handoff({
  actor: "orchestrator",
  toAgentId: "designer-agent-v1",
  instruction: "generate banner image matching text outline",
  agentContext: { prompt: "neon style workspace banner" },
});
```

### Trace Correlation & Logical Clocks (Lamport Timestamps)

Pass standard trace metadata (`traceId`, `spanId`, `parentSpanId`) to map out parent-child relationships and causality graphs between agent steps.

Volidator parses W3C `traceparent` headers automatically when you pass a request object. Telemetry contexts emitted by LangChain, LlamaIndex, or standard instrumentations are inherited without manual piping:

```typescript
await volidator.agent.toolCall({
  req: request, // Automatically extracts traceId/spanId from incoming headers
  toolName: "database_write",
  success: true,
});
```

#### Deterministic Edge Trace Ordering
To resolve NTP (Network Time Protocol) clock drift anomalies between distributed edge servers or serverless invocations, the SDK automatically maintains and propagates a **Lamport Logical Clock** value inside request headers (`x-volidator-clock`). Clocks are synchronized across boundary calls using:
$$\text{localClock} = \max(\text{localClock}, \text{incomingClock}) + 1$$
This guarantees that visualizer graphs and dashboard causality lines render completely deterministically in chronological order.

---

## 16. Batch Ingestion (`logBatch`)

For high-throughput runtimes (like agents executing iterative reasoning loops or massive data imports), use `logBatch` to prepare and send multiple logs in a single HTTP request.

All cryptographic preparation (AES-256-GCM encryption, blind indexing) runs in parallel on the client before a single POST request is made.

```typescript
const logs = [
  { actor: "agent-1", action: "thought", metadata: { step: 1 } },
  { actor: "agent-1", action: "tool_call", metadata: { toolName: "search" } },
  { actor: "agent-1", action: "thought", metadata: { step: 2 } },
];

const { accepted, rejected } = await volidator.logBatch(logs);
console.log(`Successfully ingested ${accepted} logs, failed to prepare ${rejected}`);
```

*Maximum batch size is 100 entries per request.*

---

## 17. Large Payloads (Claim Check Pattern)

When logging autonomous agent thinking processes, prompt contexts, or tool data, payloads can easily grow quite large. If your encrypted log payload exceeds **30KB**, the SDK automatically and transparently switches to the **Claim Check Pattern**:
* The SDK uploads the encrypted ciphertext chunk to Cloudflare R2 object storage securely before database ingestion.
* It writes a content-addressed SHA-256 hash pointer to the database log record instead of the full payload, setting `isClaimCheck` to true.
* The Volidator dashboard and embed widgets detect this flag and automatically retrieve the encrypted chunk from the storage proxy to decrypt it locally in the browser.

This maintains absolute Zero-Knowledge privacy guarantees for large payloads without bloat.

---

## 18. Fluent Batcher (`batcher`)

Instead of managing arrays and calling `logBatch` manually, you can use the fluent `batcher()` client helper. This is highly recommended for loop-heavy agent runs or script execution paths.

```typescript
const batcher = volidator.batcher({
  autoFlushCount: 50,      // Automatically flush and send when buffer hits 50 logs
  autoFlushInterval: 5000, // Or automatically flush every 5 seconds (Node-only, see warning)
});

// Inside your loop or agent reasoning cycle:
batcher.push({
  actor: "agent-1",
  action: "thought",
  metadata: { step: 1, text: "Thinking..." }
});

// Always call flush manually at the end of the script or request path to send any leftovers:
await batcher.flush();
```

> **⚠️ Serverless / Edge Warning:**
> `autoFlushInterval` uses `setInterval` internally. In serverless and Edge environments (like Cloudflare Workers, Vercel Edge, Next.js Edge), the V8 isolate is **frozen or destroyed** as soon as the response is returned to the user. Background timers will silently fail to execute, resulting in dropped logs.
> **Only use `autoFlushInterval` in long-lived Node.js applications** (Express, Fastify, CLI tools). For serverless/edge functions, **always manually call `await batcher.flush()`** or pass the promise to `ctx.waitUntil()`.

---

## License

MIT © Volidator Contributors
