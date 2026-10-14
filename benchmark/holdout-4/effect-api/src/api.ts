import { HttpMiddleware, HttpRouter, HttpServer } from "@effect/platform"
import { NodeContext, NodeHttpServer, NodeRuntime } from "@effect/platform-node"
import { PgClient } from "@effect/sql-pg"
import { Config, Layer } from "effect"
import { createServer } from "node:http"

import { carrierStatusCallbackRoutes } from "./http/carrier-status-callbacks.js"
import { carrierWebhookRoutes } from "./http/carrier-webhooks.js"
import { consignmentDocumentRoutes } from "./http/consignment-documents.js"
import { consignmentRoutes } from "./http/consignments.js"
import { manifestImportRoutes } from "./http/manifest-imports.js"
import { proofOfDeliveryRoutes } from "./http/proof-of-delivery.js"
import { rateSheetRoutes } from "./http/rate-sheets.js"
import { rateSheetSyncRoutes } from "./http/rate-sheet-syncs.js"
import { shipmentRoutes } from "./http/shipments.js"
import { tariffQuoteRoutes } from "./http/tariff-quotes.js"

/**
 * Northgate freight API.
 *
 * Everything in front of this process is a plain nginx reverse proxy: it
 * terminates TLS, rewrites nothing, and forwards request headers untouched.
 *
 * Partner and driver identities (see src/auth) are attached per request by the
 * routers that need them rather than by this layer graph, because they are
 * derived from the request itself.
 */
const router = HttpRouter.empty.pipe(
  HttpRouter.concat(shipmentRoutes),
  HttpRouter.concat(consignmentRoutes),
  HttpRouter.concat(consignmentDocumentRoutes),
  HttpRouter.concat(proofOfDeliveryRoutes),
  HttpRouter.concat(rateSheetRoutes),
  HttpRouter.concat(tariffQuoteRoutes),
  HttpRouter.concat(manifestImportRoutes),
  HttpRouter.concat(rateSheetSyncRoutes),
  HttpRouter.concat(carrierWebhookRoutes),
  HttpRouter.concat(carrierStatusCallbackRoutes)
)

const DatabaseLive = PgClient.layer({
  url: Config.redacted("DATABASE_URL"),
  maxConnections: Config.withDefault(Config.integer("DATABASE_POOL_SIZE"), 20),
  ssl: Config.succeed(true)
})

const ServerLive = NodeHttpServer.layer(() => createServer(), {
  port: Number.parseInt(process.env.PORT ?? "8080", 10)
})

const ApiLive = HttpServer.serve(router, HttpMiddleware.logger).pipe(
  Layer.provide(DatabaseLive),
  Layer.provide(NodeContext.layer),
  Layer.provide(ServerLive)
)

NodeRuntime.runMain(Layer.launch(ApiLive))
