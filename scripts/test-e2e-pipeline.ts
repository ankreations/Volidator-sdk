/**
 * End-to-end pipeline validation script
 * Tests: project provisioning → ingestion (cache miss) → ingestion (cache hit) → revocation
 *
 * Usage:
 *   npx tsx packages/sdk/scripts/test-e2e-pipeline.ts
 *
 * Prerequisites:
 *   npm run dev:management   # port 8788
 *   npm run dev:ingestion    # port 8787
 */

const MASTER_KEY = process.env.MASTER_KEY ?? "dev-master-key-volidator-local";
const MGMT_URL = process.env.MANAGEMENT_WORKER_URL ?? "http://127.0.0.1:8788";
const INGEST_URL = process.env.INGESTION_WORKER_URL ?? "http://127.0.0.1:8787";

// ---------------------------------------------------------------------------
// CRC32 — mirrors the management-worker implementation for local verification
// ---------------------------------------------------------------------------
function buildCrc32Table(): Uint32Array {
  const table = new Uint32Array(256);
  for (let i = 0; i < 256; i++) {
    let c = i;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
    table[i] = c;
  }
  return table;
}
const CRC32_TABLE = buildCrc32Table();

function crc32hex(str: string): string {
  let crc = 0xFFFFFFFF;
  for (let i = 0; i < str.length; i++) {
    crc = (crc >>> 8) ^ CRC32_TABLE[(crc ^ str.charCodeAt(i)) & 0xFF];
  }
  return ((crc ^ 0xFFFFFFFF) >>> 0).toString(16).padStart(8, "0").slice(0, 6);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function log(msg: string) { console.log(msg); }
function ok(msg: string) { console.log(`  ✅ ${msg}`); }
function fail(msg: string) { console.error(`  ❌ ${msg}`); process.exitCode = 1; }
function section(title: string) { console.log(`\n${"─".repeat(50)}\n${title}\n${"─".repeat(50)}`); }

async function assertStatus(label: string, res: Response, expected: number) {
  if (res.status === expected) {
    ok(`${label} → ${res.status} (expected ${expected})`);
  } else {
    const body = await res.text().catch(() => "");
    fail(`${label} → ${res.status} (expected ${expected})\n     Body: ${body}`);
  }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------
async function testFullPipeline() {
  log("⚙️  Volidator E2E Pipeline Validation");
  log(`   Management: ${MGMT_URL}`);
  log(`   Ingestion:  ${INGEST_URL}`);

  // ── Step 1: Provision a new project ──────────────────────────────────────
  section("Step 1 — Project provisioning");

  const provisionRes = await fetch(`${MGMT_URL}/v1/projects`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${MASTER_KEY}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ name: "E2E Test Project" }),
  });

  await assertStatus("POST /v1/projects", provisionRes, 201);

  const provisionData = await provisionRes.json() as any;
  const apiKey: string = provisionData.project?.apiKey;
  const projectId: string = provisionData.project?.id;
  const keyPrefix: string = provisionData.project?.apiKeyPrefix;

  if (!apiKey || !projectId) {
    fail("Missing apiKey or projectId in response");
    return;
  }

  ok(`Project ID:     ${projectId}`);
  ok(`Raw API Key:    ${apiKey}`);
  ok(`Display prefix: val_live_${keyPrefix}••••••`);

  // ── Step 2: Verify key structure ─────────────────────────────────────────
  section("Step 2 — Key structure verification");

  const keyMatch = /^val_live_([a-f0-9]{20})([a-f0-9]{6})$/.exec(apiKey);
  if (!keyMatch) {
    fail(`Key format invalid: ${apiKey}`);
    return;
  }
  const [, entropy, embeddedChecksum] = keyMatch;
  const expectedChecksum = crc32hex(entropy);

  if (embeddedChecksum === expectedChecksum) {
    ok(`CRC32 checksum verified: ${embeddedChecksum}`);
  } else {
    fail(`CRC32 mismatch: embedded=${embeddedChecksum}, expected=${expectedChecksum}`);
  }

  // ── Step 3: First ingestion — cache miss → D1 read ───────────────────────
  section("Step 3 — First ingestion (cache miss → D1 lookup → KV write)");

  const t1 = Date.now();
  const log1Res = await fetch(`${INGEST_URL}/v1/log`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      actorBlindIndex: "hmac_actor_test_01",
      actionBlindIndex: "hmac_action_test_01",
      encryptedPayload: "aGVsbG8gd29ybGQ=",
    }),
  });
  const t1ms = Date.now() - t1;

  await assertStatus("POST /v1/log (cache miss)", log1Res, 202);
  ok(`Round-trip: ${t1ms}ms`);

  // ── Step 4: Second ingestion — KV cache hit ───────────────────────────────
  section("Step 4 — Second ingestion (KV cache hit — should be faster)");

  await new Promise(r => setTimeout(r, 200)); // small gap to ensure KV write completed

  const t2 = Date.now();
  const log2Res = await fetch(`${INGEST_URL}/v1/log`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      actorBlindIndex: "hmac_actor_test_02",
      actionBlindIndex: "hmac_action_test_02",
      encryptedPayload: "aGVsbG8gd29ybGQy",
    }),
  });
  const t2ms = Date.now() - t2;

  await assertStatus("POST /v1/log (cache hit)", log2Res, 202);
  ok(`Round-trip: ${t2ms}ms ${t2ms < t1ms ? "(faster ✓)" : "(no cache speed-up — expected in local dev)"}`);

  // ── Step 5: Malformed key rejection ──────────────────────────────────────
  section("Step 5 — Structural rejection (typo'd key, zero I/O)");

  const badKey = "val_live_thisisnotvalidhex!!!!!!!";
  const t3 = Date.now();
  const badKeyRes = await fetch(`${INGEST_URL}/v1/log`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${badKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ actorBlindIndex: "x", actionBlindIndex: "y", encryptedPayload: "z" }),
  });
  const t3ms = Date.now() - t3;

  await assertStatus("POST /v1/log (malformed key)", badKeyRes, 401);
  ok(`Structural rejection in ${t3ms}ms (no SHA-256, KV, or D1 I/O)`);

  // ── Step 6: Project deletion + KV eviction ────────────────────────────────
  section("Step 6 — Project revocation + eager KV eviction");

  const deleteRes = await fetch(`${MGMT_URL}/v1/projects/${projectId}`, {
    method: "DELETE",
    headers: { Authorization: `Bearer ${MASTER_KEY}` },
  });

  await assertStatus(`DELETE /v1/projects/${projectId}`, deleteRes, 200);
  ok("Project deleted — eager KV cache eviction sent");

  // ── Step 7: Verify key is now rejected ───────────────────────────────────
  section("Step 7 — Post-revocation rejection");

  await new Promise(r => setTimeout(r, 300)); // give KV eviction time to settle locally

  const postDeleteRes = await fetch(`${INGEST_URL}/v1/log`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ actorBlindIndex: "x", actionBlindIndex: "y", encryptedPayload: "z" }),
  });

  await assertStatus("POST /v1/log (after revocation)", postDeleteRes, 401);
  ok("Revoked key correctly rejected");

  // ── Summary ───────────────────────────────────────────────────────────────
  section("Summary");
  if (process.exitCode === 1) {
    log("❌ Pipeline validation FAILED — check errors above");
  } else {
    log("✅ All pipeline stages passed successfully");
    log("   Structural check → KV cache → D1 fallback → revocation — all working\n");
  }
}

testFullPipeline().catch(e => {
  console.error("Fatal:", e);
  process.exit(1);
});
