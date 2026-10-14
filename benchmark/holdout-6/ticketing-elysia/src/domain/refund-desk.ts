import { prisma } from '../lib/prisma'

/**
 * Refund settlement. Support staff review a request, but the money that ends up
 * on the credit note is worked out here from what we actually captured for the
 * ticket - the figure the attendee typed into the request form is only ever
 * displayed, never paid out.
 */

export type SettlementResult =
  | { ok: true; creditNoteId: string; amountCents: number }
  | { ok: false; reason: 'not_reviewable' | 'nothing_refundable' }

/** What a ticket is worth back, given the event's fee policy. */
export function refundableAmountCents(input: {
  pricePaidCents: number
  feeCents: number
  retainFees: boolean
}): number {
  const refundable = input.retainFees ? input.pricePaidCents - input.feeCents : input.pricePaidCents

  return Math.max(0, Math.min(refundable, input.pricePaidCents))
}

export async function settleRefundRequest(requestId: string, reviewerAccountId: string): Promise<SettlementResult> {
  /**
   * The reviewer has to be finance staff at the organiser that owns the event
   * the ticket belongs to; that membership is part of the where clause so a
   * request from another organiser simply does not match.
   */
  const request = await prisma.refundRequest.findFirst({
    where: {
      id: requestId,
      status: 'PENDING',
      ticket: {
        event: {
          organiser: {
            staff: { some: { accountId: reviewerAccountId, role: 'FINANCE', revokedAt: null } },
          },
        },
      },
    },
    select: {
      id: true,
      requestedAmountCents: true,
      ticket: {
        select: {
          id: true,
          ownerId: true,
          currency: true,
          pricePaidCents: true,
          feeCents: true,
          event: { select: { id: true, retainFeesOnRefund: true } },
        },
      },
    },
  })

  if (!request) {
    return { ok: false, reason: 'not_reviewable' }
  }

  const amountCents = refundableAmountCents({
    pricePaidCents: request.ticket.pricePaidCents,
    feeCents: request.ticket.feeCents,
    retainFees: request.ticket.event.retainFeesOnRefund,
  })

  if (amountCents <= 0) {
    return { ok: false, reason: 'nothing_refundable' }
  }

  const [, creditNote] = await prisma.$transaction([
    prisma.refundRequest.update({
      where: { id: request.id },
      data: { status: 'APPROVED', reviewedByAccountId: reviewerAccountId, reviewedAt: new Date() },
    }),
    prisma.creditNote.create({
      data: {
        accountId: request.ticket.ownerId,
        refundRequestId: request.id,
        amountCents,
        currency: request.ticket.currency,
      },
      select: { id: true },
    }),
    prisma.ticket.update({
      where: { id: request.ticket.id },
      data: { status: 'REFUNDED' },
    }),
    prisma.account.update({
      where: { id: request.ticket.ownerId },
      data: { walletBalanceCents: { increment: amountCents } },
    }),
  ])

  return { ok: true, creditNoteId: creditNote.id, amountCents }
}
