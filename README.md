# Volidator Node.js SDK

**Zero-knowledge, server-blind audit logging for Node.js, Next.js, and edge runtimes.**

Volidator encrypts every log entry locally — on your server — before sending it. The Volidator backend stores only ciphertext and blind indexes. Your plaintext data never leaves your infrastructure unencrypted.

[![npm](https://img.shields.io/npm/v/@volidator/node)](https://www.npmjs.com/package/@volidator/node)
[![license](https://img.shields.io/npm/l/@volidator/node)](LICENSE)

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
13. [Auth Plugins](#13-auth-plugins)
14. [`@volidator/react`](#14-volidatorreact)

---

## 1. Install

```bash
npm install @volidator/node
```

---

## 2. Environment Setup

Store secrets as environment variables. Never hardcode them.

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
});
```

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

## License

MIT © Volidator Contributors
