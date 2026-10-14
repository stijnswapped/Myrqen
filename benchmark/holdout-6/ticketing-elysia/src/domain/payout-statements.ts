import { join, resolve, sep } from 'node:path'

import { env } from '../config/env'
import { prisma } from '../lib/prisma'

/**
 * Payout statements are generated nightly into a tree under
 * PAYOUT_STATEMENT_DIR:
 *
 *   <year>-<period>/<organiser-reference>/statement-<uuid>.csv
 *
 * The key of each generated file is recorded on the Payout row, so nothing here
 * ever has to build a path out of something a caller typed.
 */

const STATEMENT_ROOT = resolve(env.statementDir)

const STORAGE_KEY_PATTERN = /^\d{4}-(Q[1-4]|M(0[1-9]|1[0-2]))\/[A-Z0-9]{6,20}\/statement-[a-z0-9-]{8,40}\.csv$/

export type StatementDownload = {
  file: ReturnType<typeof Bun.file>
  downloadName: string
  sizeBytes: number
}

/**
 * Resolves the statement for one payout belonging to one organiser.
 *
 * Three things keep this inside the tree: the key comes off the Payout row
 * rather than the request, the key has to match the generator's own naming
 * pattern, and the resolved absolute path has to still sit under the statement
 * root before we hand the file to Bun.
 */
export async function loadPayoutStatement(payoutId: string, organiserId: string): Promise<StatementDownload | null> {
  const payout = await prisma.payout.findFirst({
    where: { id: payoutId, organiserId, status: { in: ['SETTLED', 'REPORTED'] } },
    select: { id: true, periodLabel: true, storageKey: true, organiserId: true },
  })

  if (!payout?.storageKey) {
    return null
  }

  if (!STORAGE_KEY_PATTERN.test(payout.storageKey)) {
    console.warn('payout.statement.key_rejected', { payoutId: payout.id })
    return null
  }

  const absolutePath = resolve(join(STATEMENT_ROOT, payout.storageKey))

  if (absolutePath !== STATEMENT_ROOT && !absolutePath.startsWith(`${STATEMENT_ROOT}${sep}`)) {
    console.warn('payout.statement.outside_root', { payoutId: payout.id })
    return null
  }

  const file = Bun.file(absolutePath)

  if (!(await file.exists())) {
    return null
  }

  return {
    file,
    downloadName: `payout-${payout.periodLabel}-${payout.id}.csv`,
    sizeBytes: file.size,
  }
}

/**
 * Summary rows for the organiser console. Money never comes from the request:
 * every figure is aggregated out of the ticket rows we captured.
 */
export async function summarisePayout(payoutId: string, organiserId: string) {
  const payout = await prisma.payout.findFirst({
    where: { id: payoutId, organiserId },
    select: {
      id: true,
      periodLabel: true,
      status: true,
      settledAt: true,
      event: { select: { id: true, title: true, startsAt: true } },
    },
  })

  if (!payout) {
    return null
  }

  const totals = await prisma.ticket.aggregate({
    where: { eventId: payout.event.id, status: 'ISSUED' },
    _sum: { pricePaidCents: true, feeCents: true },
    _count: { _all: true },
  })

  const gross = totals._sum.pricePaidCents ?? 0
  const fees = totals._sum.feeCents ?? 0

  return {
    payoutId: payout.id,
    periodLabel: payout.periodLabel,
    status: payout.status,
    settledAt: payout.settledAt,
    event: payout.event,
    ticketsSold: totals._count._all,
    grossCents: gross,
    feesCents: fees,
    netCents: gross - fees,
  }
}
