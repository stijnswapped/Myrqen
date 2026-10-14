import { cors } from '@elysiajs/cors'
import { Elysia } from 'elysia'

import { env } from './config/env'
import { eventRoutes } from './routes/events'
import { gateRoutes } from './routes/gate'
import { organiserEventRoutes } from './routes/organiser-events'
import { payoutRoutes } from './routes/payouts'
import { promotionRoutes } from './routes/promotions'
import { refundRoutes } from './routes/refunds'
import { ticketRoutes } from './routes/tickets'
import { walletRoutes } from './routes/wallet'
import { disconnectPrisma, prisma } from './lib/prisma'

export const app = new Elysia()
  .use(cors({ origin: env.allowedOrigins, credentials: true }))
  .onError(({ code, error, status, path }) => {
    if (code === 'VALIDATION') {
      return status(422, { error: 'request_invalid' })
    }

    if (code === 'NOT_FOUND') {
      return status(404, { error: 'route_not_found' })
    }

    // Never let a driver message reach the client; the request id in the log is
    // what support asks for.
    console.error('request.failed', { path, code, message: error instanceof Error ? error.message : String(error) })

    return status(500, { error: 'internal_error' })
  })
  .get('/healthz', async () => {
    await prisma.$queryRaw`SELECT 1`

    return { ok: true, env: env.nodeEnv }
  })
  .use(eventRoutes)
  .use(organiserEventRoutes)
  .use(ticketRoutes)
  .use(walletRoutes)
  .use(gateRoutes)
  .use(payoutRoutes)
  .use(promotionRoutes)
  .use(refundRoutes)

process.on('SIGTERM', async () => {
  await app.stop()
  await disconnectPrisma()
})

app.listen(env.port)

console.log(`gatefold ticketing api listening on :${env.port}`)
