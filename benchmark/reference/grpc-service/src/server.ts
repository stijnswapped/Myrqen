import path from 'node:path'
import { fileURLToPath } from 'node:url'

import * as grpc from '@grpc/grpc-js'
import * as protoLoader from '@grpc/proto-loader'

import { closePool } from './lib/db.js'
import { buildCostReport } from './handlers/cost-reports.js'
import { getDepotThroughput } from './handlers/depot-throughput.js'
import { adjustStock } from './handlers/stock-adjustments.js'
import { transferStock } from './handlers/stock-transfers.js'
import { getPurchaseOrder } from './handlers/purchase-orders.js'
import { getGoodsReceipt } from './handlers/goods-receipts.js'
import { submitCycleCount } from './handlers/cycle-counts.js'
import { approveCycleCount } from './handlers/stock-count-approvals.js'
import { streamInventoryAudit } from './handlers/inventory-audit-stream.js'
import { getInvoiceDocument } from './handlers/invoice-documents.js'
import { getSupplierStatement } from './handlers/supplier-statements.js'

const here = path.dirname(fileURLToPath(import.meta.url))
const PROTO_ROOT = path.resolve(here, '../proto')
const PROTO_PATH = path.join(PROTO_ROOT, 'depot/v1/depot.proto')

const definition = protoLoader.loadSync(PROTO_PATH, {
  keepCase: false,
  longs: String,
  enums: String,
  defaults: true,
  oneofs: true,
  includeDirs: [PROTO_ROOT],
})

interface DepotPackage {
  depot: { v1: { DepotService: grpc.ServiceClientConstructor } }
}

const descriptor = grpc.loadPackageDefinition(definition) as unknown as DepotPackage

/**
 * Access log and latency histogram feed.
 *
 * Authorisation is deliberately not done here. The rules differ per method
 * — some are internal-only, some are depot scoped, some are finance only —
 * so every handler resolves its own claims and states its own rule.
 */
const accessLog: grpc.ServerInterceptor = (methodDescriptor, call) => {
  const startedAt = process.hrtime.bigint()
  return new grpc.ServerInterceptingCall(call, {
    sendStatus(status, next) {
      const elapsedMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      console.info(
        '[depot] rpc %s %s %sms',
        methodDescriptor.path,
        grpc.status[status.code],
        elapsedMs.toFixed(1),
      )
      next(status)
    },
  })
}

export function buildServer(): grpc.Server {
  const server = new grpc.Server({
    interceptors: [accessLog],
    'grpc.max_receive_message_length': 8 * 1024 * 1024,
    'grpc.max_send_message_length': 32 * 1024 * 1024,
  })

  server.addService(descriptor.depot.v1.DepotService.service, {
    buildCostReport,
    getDepotThroughput,
    adjustStock,
    transferStock,
    getPurchaseOrder,
    getGoodsReceipt,
    submitCycleCount,
    approveCycleCount,
    streamInventoryAudit,
    getInvoiceDocument,
    getSupplierStatement,
  })

  return server
}

async function main(): Promise<void> {
  const address = process.env.DEPOT_GRPC_ADDRESS ?? '0.0.0.0:50051'
  const server = buildServer()

  // TLS is terminated by the mesh sidecar, so the process itself listens
  // in the clear on the pod network. Nothing outside the VPC can dial it:
  // the NLB in front of the namespace only accepts the platform CIDRs.
  await new Promise<void>((resolve, reject) => {
    server.bindAsync(address, grpc.ServerCredentials.createInsecure(), (err, port) => {
      if (err) {
        reject(err)
        return
      }
      console.info('[depot] depot.v1.DepotService listening on port %d', port)
      resolve()
    })
  })

  const shutdown = (signal: string) => {
    console.info('[depot] %s received, draining', signal)
    server.tryShutdown(async () => {
      await closePool()
      process.exit(0)
    })
  }

  process.on('SIGTERM', () => shutdown('SIGTERM'))
  process.on('SIGINT', () => shutdown('SIGINT'))
}

if (process.env.NODE_ENV !== 'test') {
  main().catch((err) => {
    console.error('[depot] failed to start', err)
    process.exit(1)
  })
}
