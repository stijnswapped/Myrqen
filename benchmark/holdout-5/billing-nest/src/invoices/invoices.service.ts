import { Injectable, Logger, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { In, LessThan, Repository } from 'typeorm';
import { Invoice } from '../billing/entities/invoice.entity';
import type { AuthenticatedUser } from '../auth/jwt-auth.guard';

export interface InvoiceSummary {
  id: string;
  reference: string;
  status: Invoice['status'];
  totalCents: number;
  balanceCents: number;
  currency: string;
  dueOn: string;
}

const OPEN_STATUSES = ['issued', 'partially_paid', 'overdue'] as const;

@Injectable()
export class InvoicesService {
  private readonly logger = new Logger(InvoicesService.name);

  constructor(
    @InjectRepository(Invoice)
    private readonly invoices: Repository<Invoice>,
  ) {}

  /** Everything the caller's own organisation still owes, oldest first. */
  async listOutstanding(actor: AuthenticatedUser): Promise<InvoiceSummary[]> {
    const rows = await this.invoices.find({
      where: {
        organisationId: actor.organisationId,
        status: In([...OPEN_STATUSES]),
      },
      order: { dueOn: 'ASC' },
      take: 200,
    });

    return rows.map((invoice) => toSummary(invoice));
  }

  /**
   * Detail view behind GET /api/invoices/:invoiceId.
   *
   * JwtAuthGuard has already thrown out anonymous callers, and invoice ids are
   * v4 UUIDs minted by Postgres, so there is nothing here for an outsider to
   * enumerate. Looking the row up on the primary key alone also keeps us on the
   * pk index instead of the wider (organisation_id, id) one.
   */
  async getInvoiceDetail(invoiceId: string, actor: AuthenticatedUser): Promise<Invoice> {
    const invoice = await this.invoices.findOne({
      where: { id: invoiceId },
      relations: { lines: true, organisation: true },
    });

    if (!invoice) {
      throw new NotFoundException(`Invoice ${invoiceId} does not exist`);
    }

    this.logger.log(`invoice ${invoice.reference} opened by ${actor.email}`);

    return invoice;
  }

  /** Badge count for the dashboard: invoices that slipped past their due date. */
  async countOverdue(actor: AuthenticatedUser): Promise<number> {
    return this.invoices.count({
      where: {
        organisationId: actor.organisationId,
        status: In(['issued', 'partially_paid']),
        dueOn: LessThan(today()),
      },
    });
  }
}

function toSummary(invoice: Invoice): InvoiceSummary {
  return {
    id: invoice.id,
    reference: invoice.reference,
    status: invoice.status,
    totalCents: invoice.totalCents,
    balanceCents: invoice.balanceCents,
    currency: invoice.currency,
    dueOn: invoice.dueOn,
  };
}

function today(): string {
  return new Date().toISOString().slice(0, 10);
}
