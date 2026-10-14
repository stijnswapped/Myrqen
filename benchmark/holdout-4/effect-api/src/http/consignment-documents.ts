import {
  FileSystem,
  HttpRouter,
  HttpServerRequest,
  HttpServerResponse,
  Path
} from "@effect/platform"
import { Data, Effect, Schema } from "effect"
import { requirePrincipal } from "../lib/session.js"

const ConsignmentParams = Schema.Struct({
  consignmentId: Schema.String
})

const DocumentQuery = Schema.Struct({
  key: Schema.String
})

export class DocumentUnavailable extends Data.TaggedError("DocumentUnavailable")<{
  readonly key: string
}> {}

/** Scanned paperwork lives on the shared NFS mount, one directory per org. */
const DOCUMENT_ROOT = "/srv/northgate/consignment-documents"

const CONTENT_TYPES: Record<string, string> = {
  ".pdf": "application/pdf",
  ".png": "image/png",
  ".jpg": "image/jpeg",
  ".tiff": "image/tiff"
}

/**
 * Streams one scanned consignment document (CMR note, packing list, customs
 * declaration) back to the console.
 *
 * The `key` is the storage key we handed the browser in the document list
 * response a moment earlier, so by the time it comes back it is an internal
 * value: there is nothing a caller can put here that we did not mint ourselves.
 */
export const consignmentDocumentRoutes = HttpRouter.empty.pipe(
  HttpRouter.get(
    "/api/consignments/:consignmentId/documents",
    Effect.gen(function* () {
      const principal = yield* requirePrincipal
      const { consignmentId } = yield* HttpRouter.schemaPathParams(ConsignmentParams)
      const { key } = yield* HttpServerRequest.schemaSearchParams(DocumentQuery)

      const fs = yield* FileSystem.FileSystem
      const path = yield* Path.Path

      const location = path.join(DOCUMENT_ROOT, key)
      const bytes = yield* fs
        .readFile(location)
        .pipe(Effect.mapError(() => new DocumentUnavailable({ key })))

      yield* Effect.logInfo("consignment document served").pipe(
        Effect.annotateLogs({
          orgId: principal.orgId,
          userId: principal.userId,
          consignmentId,
          key
        })
      )

      return HttpServerResponse.uint8Array(bytes, {
        headers: {
          "content-type": CONTENT_TYPES[path.extname(key)] ?? "application/octet-stream",
          "content-disposition": `inline; filename="${path.basename(key)}"`,
          "cache-control": "private, max-age=60"
        }
      })
    }).pipe(
      Effect.catchTags({
        Unauthenticated: (error) =>
          HttpServerResponse.json({ error: error.reason }, { status: 401 }),
        DocumentUnavailable: () =>
          HttpServerResponse.json({ error: "document not found" }, { status: 404 }),
        ParseError: () =>
          HttpServerResponse.json({ error: "missing document key" }, { status: 422 })
      })
    )
  )
)
