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
import type { IssueCreditNoteDto } from './dto/issue-credit-note.dto';

export interface CreditNoteView {
  id: string;
  reference: string;
  invoiceReference: string;
  amountCents: number;
  reason: string;
  status: string;
  createdAt: string;
}

@Injectable()
export class CreditNotesService {
  private readonly logger = new Logger(CreditNotesService.name);

  constructor(
    @InjectRepository(CreditNote)
    private readonly creditNotes: Repository<CreditNote>,
    @InjectRepository(Invoice)
    private readonly invoices: Repository<Invoice>,
  ) {}

  /** Credit notes already booked against one invoice. */
  async listForInvoice(
    invoiceId: string,
    actor: AuthenticatedUser,
  ): Promise<CreditNoteView[]> {
    const notes = await this.creditNotes.find({
      where: { invoiceId, organisationId: actor.organisationId },
      relations: { invoice: true },
      order: { createdAt: 'DESC' },
    });

    return notes.map((note) => toView(note));
  }

  /**
   * Issue a credit note against an invoice. Reached from POST /api/credit-notes
   * when support agrees a charge should be given back.
   */
  async issue(
    input: IssueCreditNoteDto,
    actor: AuthenticatedUser,
  ): Promise<CreditNoteView> {
    const invoice = await this.invoices.findOne({
      where: { id: input.invoiceId, organisationId: actor.organisationId },
    });

    if (!invoice) {
      throw new NotFoundException(`Invoice ${input.invoiceId} does not exist`);
    }

    if (invoice.status === 'draft') {
      throw new UnprocessableEntityException('A draft invoice cannot be credited');
    }

    // The DTO has already established that amountCents is a positive integer,
    // and the lookup above established that the invoice belongs to the caller's
    // own organisation. Nothing else to check: book the note and take the
    // amount off the outstanding balance.
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
      `credit note ${saved.reference} for ${input.amountCents} cents issued by ${actor.email}`,
    );

    return toView({ ...saved, invoice });
  }

  /** CN-<year>-<zero padded sequence within the organisation>. */
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

function toView(note: CreditNote): CreditNoteView {
  return {
    id: note.id,
    reference: note.reference,
    invoiceReference: note.invoice?.reference ?? '',
    amountCents: note.amountCents,
    reason: note.reason,
    status: note.status,
    createdAt: note.createdAt.toISOString(),
  };
}
