import { PrismaClient } from '@prisma/client'

import { env } from '../config/env'

/**
 * Bun's watch mode re-evaluates modules on every save, which used to leave a
 * fan of orphaned pools behind. Keeping the client on globalThis outside of
 * production fixes that.
 */
const globalForPrisma = globalThis as unknown as { prismaClient?: PrismaClient }

export const prisma =
  globalForPrisma.prismaClient ??
  new PrismaClient({
    datasources: { db: { url: env.databaseUrl } },
    log: env.nodeEnv === 'production' ? ['warn', 'error'] : ['query', 'warn', 'error'],
  })

if (env.nodeEnv !== 'production') {
  globalForPrisma.prismaClient = prisma
}

export async function disconnectPrisma(): Promise<void> {
  await prisma.$disconnect()
}
