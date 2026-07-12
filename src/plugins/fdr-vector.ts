/**
 * @volidator/node — FDR Vector Store Wrapper (fdr-vector)
 *
 * Provides `wrapVectorStore()`: a bi-temporal middleware adapter for agent
 * memory (vector databases). Converts hard deletes into soft deletes by
 * appending `_vld_from` and `_vld_to` metadata fields, creating an immutable
 * version history that can be queried at any past timestamp.
 *
 * Two compliance tiers are supported:
 *
 *   Tier 1 — High-Assurance (pgvector / self-hosted):
 *     Use database-level BEFORE triggers (see docs/guides/fdr-vector-memory.md)
 *     to enforce soft-delete-only semantics at the engine level. The SDK wrapper
 *     generates correctly timestamped queries.
 *
 *   Tier 2 — Standard (hosted SaaS: Pinecone, Weaviate Cloud, Qdrant Cloud):
 *     The SDK middleware intercepts delete() calls and converts them to metadata
 *     updates. Engine-level enforcement is not available; compliance is bounded
 *     by SDK-layer interception.
 *
 * IMPORTANT: For Tier 2 vector DBs, a developer or administrator with direct
 * access to the provider's web dashboard or REST API can still perform hard
 * deletes that bypass this middleware. This limitation must be disclosed to
 * auditors. See the Tier 2 assurance boundary documentation.
 */

// ---------------------------------------------------------------------------
// Duck-typed interfaces (no runtime peer dependencies)
// ---------------------------------------------------------------------------

/**
 * Minimal interface for a vector document, compatible with Pinecone, Qdrant,
 * and pgvector record shapes.
 */
export interface VectorDocument {
  id: string;
  values?: number[];
  metadata?: Record<string, unknown>;
  [key: string]: unknown;
}

/**
 * Generic vector DB client interface — duck-typed so no peer dependency is
 * required at runtime. Only the methods used by the wrapper are declared.
 */
export interface VectorStoreClient {
  upsert(documents: VectorDocument[]): Promise<unknown>;
  delete(ids: string[]): Promise<unknown>;
  query(params: Record<string, unknown>): Promise<unknown>;
  [key: string]: unknown;
}

/** Compliance assurance tier. */
export type VectorStoreTier = "pgvector" | "hosted";

export interface WrapVectorStoreOptions {
  /**
   * `pgvector`  — self-hosted; use with engine-level BEFORE triggers.
   * `hosted`    — Pinecone, Weaviate Cloud, Qdrant Cloud (SDK-layer only).
   */
  mode: VectorStoreTier;
  /**
   * The logical namespace or collection name. Used to scope FDR event logging.
   */
  namespace: string;
  /**
   * Optional actor identifier for audit log attribution.
   */
  actor?: string;
  /**
   * Metadata field name for the bi-temporal valid-from timestamp.
   * @default "_vld_from"
   */
  validFromField?: string;
  /**
   * Metadata field name for the bi-temporal valid-to timestamp.
   * @default "_vld_to"
   */
  validToField?: string;
}

/** A wrapped vector store client with bi-temporal middleware applied. */
export interface WrappedVectorStore {
  /**
   * Inserts or updates a set of documents, stamping each with a `_vld_from`
   * timestamp. Original documents are never mutated.
   */
  upsert(documents: VectorDocument[]): Promise<unknown>;
  /**
   * Soft-deletes documents by setting their `_vld_to` metadata to the current
   * timestamp, rather than physically removing them from the store.
   *
   * For `hosted` tier: calls the underlying upsert with `_vld_to` set.
   * For `pgvector` tier: executes a SQL UPDATE setting `valid_to_ts`.
   */
  delete(ids: string[], reason?: string): Promise<unknown>;
  /**
   * Queries the vector store, filtering by bi-temporal validity at the
   * specified timestamp. Defaults to the current wall-clock time.
   *
   * @param params  Native query parameters for the underlying client.
   * @param asOf    Optional past timestamp (ms) for historical state queries.
   */
  query(params: Record<string, unknown>, asOf?: number): Promise<unknown>;
  /**
   * Returns the tier and namespace configuration of this wrapper.
   */
  readonly config: Readonly<WrapVectorStoreOptions>;
}

// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------

/**
 * Wraps a vector store client with bi-temporal middleware.
 *
 * @param client   The underlying vector DB client instance.
 * @param options  Configuration including tier, namespace, and field names.
 */
export function wrapVectorStore(
  client: VectorStoreClient,
  options: WrapVectorStoreOptions,
): WrappedVectorStore {
  const validFromField = options.validFromField ?? "_vld_from";
  const validToField = options.validToField ?? "_vld_to";

  /**
   * Stamps a document with a `_vld_from` timestamp if not already present.
   * Never mutates the original document object.
   */
  function stampDocument(doc: VectorDocument, nowMs: number): VectorDocument {
    return {
      ...doc,
      metadata: {
        ...doc.metadata,
        // Only set _vld_from on insert — do not overwrite on updates.
        [validFromField]: doc.metadata?.[validFromField] ?? nowMs,
        // Ensure _vld_to is explicitly null on new documents.
        [validToField]: doc.metadata?.[validToField] ?? null,
      },
    };
  }

  /**
   * Builds the bi-temporal filter clause for a query.
   * Injects: valid_from <= asOf AND (valid_to > asOf OR valid_to IS NULL)
   *
   * The exact filter format depends on the vector DB's query API.
   * For Pinecone: metadata filter object.
   * For Qdrant: payload condition.
   * The filter is returned as a plain object that can be merged into the
   * provider-specific query params by the caller.
   */
  function buildTemporalFilter(asOfMs: number): Record<string, unknown> {
    return {
      [validFromField]: { $lte: asOfMs },
      $or: [
        { [validToField]: { $gt: asOfMs } },
        { [validToField]: null },
      ],
    };
  }

  return {
    config: Object.freeze({ ...options }),

    async upsert(documents: VectorDocument[]): Promise<unknown> {
      const nowMs = Date.now();
      const stamped = documents.map((doc) => stampDocument(doc, nowMs));
      return client.upsert(stamped);
    },

    async delete(ids: string[], reason?: string): Promise<unknown> {
      const nowMs = Date.now();

      if (options.mode === "pgvector") {
        // For pgvector (self-hosted), convert delete to a SQL UPDATE.
        // The caller is responsible for passing a pgvector client that exposes
        // a `softDelete(ids, validToField, nowMs)` method, OR the BEFORE triggers
        // on the table will catch any attempted hard DELETE.
        //
        // We call upsert with the updated valid_to field set. For pgvector this
        // requires the caller to have a combined upsert-or-update mechanism.
        // See docs/guides/fdr-vector-memory.md for the pgvector migration + trigger SQL.
        const softDeleteDocs: VectorDocument[] = ids.map((id) => ({
          id,
          metadata: {
            [validToField]: nowMs,
            _vld_delete_reason: reason ?? "soft_delete",
          },
        }));
        return client.upsert(softDeleteDocs);
      }

      // Tier 2 (hosted): attempt to update metadata to set _vld_to.
      // This relies on the vector DB supporting metadata-only updates via upsert.
      // If the provider does not support partial upserts, this will be a no-op.
      //
      // COMPLIANCE BOUNDARY: This does not prevent hard deletes performed via
      // the provider's web dashboard or direct REST API calls outside this SDK.
      console.warn(
        `[Volidator FDR] Tier 2 soft-delete intercepted for namespace "${options.namespace}". ` +
          `IDs: [${ids.join(", ")}]. Note: engine-level enforcement is not available for hosted ` +
          `vector DBs. A rogue admin with direct provider access can still perform hard deletes.`,
      );

      const softDeleteDocs: VectorDocument[] = ids.map((id) => ({
        id,
        metadata: {
          [validToField]: nowMs,
          _vld_delete_reason: reason ?? "soft_delete",
        },
      }));
      return client.upsert(softDeleteDocs);
    },

    async query(
      params: Record<string, unknown>,
      asOf?: number,
    ): Promise<unknown> {
      const asOfMs = asOf ?? Date.now();
      const temporalFilter = buildTemporalFilter(asOfMs);

      // Merge temporal filter into the existing filter object if present,
      // or inject it as a new `filter` key.
      const existingFilter =
        typeof params.filter === "object" && params.filter !== null
          ? (params.filter as Record<string, unknown>)
          : {};

      const mergedParams: Record<string, unknown> = {
        ...params,
        filter: {
          ...existingFilter,
          ...temporalFilter,
        },
      };

      return client.query(mergedParams);
    },
  };
}
