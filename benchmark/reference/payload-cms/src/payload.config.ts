import path from 'node:path'
import { fileURLToPath } from 'node:url'

import { mongooseAdapter } from '@payloadcms/db-mongodb'
import { lexicalEditor } from '@payloadcms/richtext-lexical'
import { buildConfig } from 'payload'

import { Invoices } from './collections/Invoices'
import { PayoutAccounts } from './collections/PayoutAccounts'
import { PurchaseOrders } from './collections/PurchaseOrders'
import { Tenants } from './collections/Tenants'
import { Users } from './collections/Users'
import { attachmentDownloadEndpoint } from './endpoints/attachment-download'
import { invoiceReferenceLookupEndpoint } from './endpoints/invoice-reference-lookup'
import { invoiceStatementEndpoint } from './endpoints/invoice-statements'
import { orderFeedEndpoint } from './endpoints/order-feed'
import { orderTrackingEndpoint } from './endpoints/order-tracking'
import { reportExportEndpoint } from './endpoints/report-export'

const dirname = path.dirname(fileURLToPath(import.meta.url))

const serverURL = process.env.PAYLOAD_PUBLIC_SERVER_URL ?? 'http://localhost:3000'

const payloadSecret = process.env.PAYLOAD_SECRET
if (!payloadSecret) {
  throw new Error('PAYLOAD_SECRET is required. Copy .env.example and fill it in before booting.')
}

export default buildConfig({
  serverURL,
  routes: {
    // Root-level endpoints below are served under this prefix, so
    // `path: '/order-feed'` answers on GET /api/order-feed.
    api: '/api',
    admin: '/admin',
  },
  admin: {
    user: Users.slug,
    importMap: { baseDir: path.resolve(dirname) },
    meta: { titleSuffix: ' — Orderbook' },
  },
  collections: [Users, Tenants, PurchaseOrders, Invoices, PayoutAccounts],
  endpoints: [
    orderTrackingEndpoint,
    invoiceReferenceLookupEndpoint,
    invoiceStatementEndpoint,
    orderFeedEndpoint,
    attachmentDownloadEndpoint,
    reportExportEndpoint,
  ],
  editor: lexicalEditor(),
  secret: payloadSecret,
  typescript: { outputFile: path.resolve(dirname, 'payload-types.ts') },
  db: mongooseAdapter({
    // Local development database; staging and production come from the env.
    url: process.env.DATABASE_URI ?? 'mongodb://orderbook:orderbook@localhost:27017/orderbook',
  }),
  cors: [serverURL],
  csrf: [serverURL],
  graphQL: { disable: false },
  telemetry: false,
})
