import {
  Injectable,
  Logger,
  NotFoundException,
  UnprocessableEntityException,
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { CreditNote } from '../billing/entities/credit-note.entity';
import { Invoice } from '../billing/entities/invoice.entity';
import type { AuthenticatedUser } from '../auth/jwt-auth.guard';
import type { ApproveRefundDto } from './dto/approve-refund.dto';

export interface RefundReceipt {
  creditNoteReference: string;
  invoiceReference: string;
  amountCents: number;
  remainingCreditableCents: number;
}

@Injectable()
export class RefundApprovalService {
  private readonly logger = new Logger(RefundApprovalService.name);

  constructor(
    @InjectRepository(CreditNote)
    private readonly creditNotes: Repository<CreditNote>,
    @InjectRepository(Invoice)
    private readonly invoices: Repository<Invoice>,
  ) {}

  /**
   * Approve a cash refund on an already paid invoice. Reached from
   * POST /api/refunds.
   */
  async approve(
    input: ApproveRefundDto,
    actor: AuthenticatedUser,
  ): Promise<RefundReceipt> {
    const invoice = await this.invoices.findOne({
      where: { id: input.invoiceId, organisationId: actor.organisationId },
    });

    if (!invoice) {
      throw new NotFoundException(`Invoice ${input.invoiceId} does not exist`);
    }

    if (invoice.status === 'draft') {
      throw new UnprocessableEntityException('A draft invoice cannot be refunded');
    }

    // What is left to give back is the invoice total minus everything already
    // credited or refunded against it. Anything above that would push the
    // account into a negative balance the payment provider would then pay out.
    const creditedSoFar = await this.creditedCents(invoice.id);
    const remainingCreditableCents = invoice.totalCents - creditedSoFar;

    if (input.amountCents > remainingCreditableCents) {
      throw new UnprocessableEntityException(
        `Only ${remainingCreditableCents} cents of invoice ${invoice.reference} can still be credited`,
      );
    }

    const note = this.creditNotes.create({
      organisationId: invoice.organisationId,
      invoiceId: invoice.id,
      reference: await this.nextReference(invoice.organisationId),
      amountCents: input.amountCents,
      reason: input.reason,
      status: 'issued',
      issuedById: actor.id,
    });

    const saved = await this.creditNotes.save(note);

    await this.invoices.decrement(
      { id: invoice.id },
      'balanceCents',
      input.amountCents,
    );

    this.logger.log(
      `refund ${saved.reference} of ${input.amountCents} cents approved by ${actor.email}`,
    );

    return {
      creditNoteReference: saved.reference,
      invoiceReference: invoice.reference,
      amountCents: saved.amountCents,
      remainingCreditableCents: remainingCreditableCents - saved.amountCents,
    };
  }

  /** Sum of every credit note on the invoice that has not been voided. */
  private async creditedCents(invoiceId: string): Promise<number> {
    const row = await this.creditNotes
      .createQueryBuilder('note')
      .select('COALESCE(SUM(note.amountCents), 0)', 'total')
      .where('note.invoiceId = :invoiceId', { invoiceId })
      .andWhere('note.status <> :voided', { voided: 'voided' })
      .getRawOne<{ total: string }>();

    return Number(row?.total ?? 0);
  }

  private async nextReference(organisationId: string): Promise<string> {
    const year = new Date().getUTCFullYear();
    const issuedThisYear = await this.creditNotes
      .createQueryBuilder('note')
      .where('note.organisationId = :organisationId', { organisationId })
      .andWhere('note.reference LIKE :prefix', { prefix: `CN-${year}-%` })
      .getCount();

    return `CN-${year}-${String(issuedThisYear + 1).padStart(6, '0')}`;
  }
}
