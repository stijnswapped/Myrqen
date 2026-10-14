import { FileSystem, HttpRouter, HttpServerResponse, Path } from "@effect/platform"
import { SqlClient } from "@effect/sql"
import { Data, Effect, Schema } from "effect"
import { requirePrincipal } from "../lib/session.js"

const ConsignmentParams = Schema.Struct({
  consignmentId: Schema.String
})

const StoredDocument = Schema.Struct({
  storage_key: Schema.String,
  content_type: Schema.String,
  captured_at: Schema.DateFromSelf
})

export class ProofUnavailable extends Data.TaggedError("ProofUnavailable")<{
  readonly consignmentId: string
}> {}

const DOCUMENT_ROOT = "/srv/northgate/consignment-documents"

/**
 * Returns the signed proof-of-delivery image for a consignment. The caller
 * never names a file: the storage key is looked up from the row that belongs to
 * their own organisation, and the resolved path is checked to still sit under
 * the document root before anything is read.
 */
export const proofOfDeliveryRoutes = HttpRouter.empty.pipe(
  HttpRouter.get(
    "/api/consignments/:consignmentId/pod",
    Effect.gen(function* () {
      const principal = yield* requirePrincipal
      const { consignmentId } = yield* HttpRouter.schemaPathParams(ConsignmentParams)

      const sql = yield* SqlClient.SqlClient
      const fs = yield* FileSystem.FileSystem
      const path = yield* Path.Path

      const rows = yield* sql`
        select storage_key, content_type, captured_at
        from consignment_documents
        where consignment_id = ${consignmentId}
          and org_id = ${principal.orgId}
          and kind = 'proof_of_delivery'
        order by captured_at desc
        limit 1
      `.pipe(Effect.orDie)

      const candidate = rows[0]
      if (candidate === undefined) {
        return yield* new ProofUnavailable({ consignmentId })
      }

      const stored = yield* Schema.decodeUnknown(StoredDocument)(candidate).pipe(Effect.orDie)
      const location = path.resolve(DOCUMENT_ROOT, stored.storage_key)
      if (!location.startsWith(DOCUMENT_ROOT + path.sep)) {
        yield* Effect.logError("storage key escaped the document root").pipe(
          Effect.annotateLogs({ consignmentId, storageKey: stored.storage_key })
        )
        return yield* new ProofUnavailable({ consignmentId })
      }

      const bytes = yield* fs
        .readFile(location)
        .pipe(Effect.mapError(() => new ProofUnavailable({ consignmentId })))

      return HttpServerResponse.uint8Array(bytes, {
        headers: {
          "content-type": stored.content_type,
          "content-disposition": `inline; filename="pod-${consignmentId}"`,
          "cache-control": "private, max-age=60"
        }
      })
    }).pipe(
      Effect.catchTags({
        Unauthenticated: (error) =>
          HttpServerResponse.json({ error: error.reason }, { status: 401 }),
        ProofUnavailable: () =>
          HttpServerResponse.json({ error: "no proof of delivery on file" }, { status: 404 }),
        ParseError: () =>
          HttpServerResponse.json({ error: "bad consignment id" }, { status: 422 })
      })
    )
  )
)
