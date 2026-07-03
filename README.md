# Volidator Node.js SDK (Zero-Knowledge Audit Logging)

Volidator is a Zero-Knowledge, server-blind audit logging client. This SDK lets you send security and activity logs from your Node.js or TypeScript backend directly to Volidator.

---

## How does Zero-Knowledge logging work?

Imagine you want to save letters in a locker box, but you do not want the locker company to read them.
1. **You keep a secret key** (held only on your server, never shared with the locker company).
2. **Before sending a letter**, you lock it inside a lockbox using your key.
3. **The locker company stores the box**, but since they do not have your key, they only see a closed metal box.
4. **When you want to read your letters**, you retrieve the locked box and unlock it locally in your browser.

This is what this SDK does. It encrypts your audit logs locally before they ever leave your server. The Volidator database only stores encrypted text.

---

## 1. Install the SDK

Run this command in your project directory:

```bash
npm install @volidator/node
```

---

## 2. Set Up Your Environment Secrets

Do not put secret keys directly in your code. Save them as environment variables (secrets) on your server:

```bash
# The API key authenticates your server (used by the ingestion worker)
VOLIDATOR_API_KEY="val_live_xxxxxxxx..."

# The Encryption Key (DEK) used to lock your logs locally before sending
VOLIDATOR_ENCRYPTION_KEY="vol-dek-xxxxxxxx..."
```

---

## 3. Initialize the Client

Create a single instance of `VolidatorClient` in your app and reuse it. Do not initialize it for every request.

```typescript
import { VolidatorClient } from "@volidator/node";

export const volidator = new VolidatorClient({
  apiKey: process.env.VOLIDATOR_API_KEY!,
  encryptionKey: process.env.VOLIDATOR_ENCRYPTION_KEY!,
});
```

---

## 4. Send Your First Audit Log

Call `volidator.log` when important actions happen (like logins, deletes, or setting changes):

```typescript
// Example: Logging a successful user login
await volidator.log({
  actor: "user_usr_12345",         // Who did it
  action: "user.login.success",    // What happened
  target: "workspace_abc789",      // What they worked on
  metadata: {
    deviceName: "MacBook Pro",
    authProvider: "Google OAuth"
  }
});
```

The `log()` method returns a boolean (`true` if log was accepted, `false` otherwise) and handles internal queue/failures gracefully without throwing runtime errors.

---

## 5. Pass Request Context Automatically

Pass your framework's HTTP request object directly. The SDK automatically extracts IP address, User-Agent, and geolocation details safely:

```typescript
// In a Next.js API Route Handler or Express.js middleware:
await volidator.log({
  actor: session.userId,
  action: "settings.update",
  req: request, // Passes the request object directly
  metadata: {
    fieldChanged: "email_address"
  }
});
```

Supported request formats:
- Node.js HTTP `IncomingMessage`
- Standard Web `Request` (Next.js, Cloudflare Workers, etc.)

---

## 6. Control Telemetry (IP / UA Tracking)

If you have strict privacy policies, you can adjust telemetry presets in the constructor:

```typescript
const volidator = new VolidatorClient({
  apiKey: process.env.VOLIDATOR_API_KEY!,
  encryptionKey: process.env.VOLIDATOR_ENCRYPTION_KEY!,
  telemetry: {
    ip: "anonymize",       // "track" | "anonymize" (hashes IP) | "skip"
    userAgent: "parse",    // "track" | "parse" (identifies browser/OS) | "skip"
    location: false        // Set to false to disable country/city tracking
  }
});
```

---

## 7. PII Redaction (GDPR and HIPAA compliance)

Prevent sensitive data from ever being encrypted or sent:

```typescript
const volidator = new VolidatorClient({
  apiKey: process.env.VOLIDATOR_API_KEY!,
  encryptionKey: process.env.VOLIDATOR_ENCRYPTION_KEY!,
  
  // Replaces the value with "[REDACTED]" before hashing or encrypting
  redactKeys: ["actor", "metadata.socialSecurityNumber"]
});
```
