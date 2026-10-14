import { Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Invoice } from '../billing/entities/invoice.entity';
import type { AuthenticatedUser } from '../auth/jwt-auth.guard';

export interface InvoiceLineView {
  id: string;
  description: string;
  quantity: number;
  unitPriceCents: number;
  taxRateBps: number;
  netCents: number;
  taxCents: number;
}

@Injectable()
export class InvoiceLinesService {
  constructor(
    @InjectRepository(Invoice)
    private readonly invoices: Repository<Invoice>,
  ) {}

  /**
   * Line items behind GET /api/invoices/:invoiceId/lines.
   *
   * The invoice id comes off the URL, so the organisation of the caller is part
   * of the lookup rather than something we check afterwards: an id that belongs
   * to another tenant simply does not match a row and comes back as a 404.
   */
  async listForInvoice(
    invoiceId: string,
    actor: AuthenticatedUser,
  ): Promise<InvoiceLineView[]> {
    const invoice = await this.invoices.findOne({
      where: { id: invoiceId, organisationId: actor.organisationId },
      relations: { lines: true },
    });

    if (!invoice) {
      throw new NotFoundException(`Invoice ${invoiceId} does not exist`);
    }

    return invoice.lines.map((line) => {
      const netCents = line.quantity * line.unitPriceCents;

      return {
        id: line.id,
        description: line.description,
        quantity: line.quantity,
        unitPriceCents: line.unitPriceCents,
        taxRateBps: line.taxRateBps,
        netCents,
        taxCents: Math.round((netCents * line.taxRateBps) / 10_000),
      };
    });
  }

  /** Total tax charged on an invoice, used by the VAT return export. */
  async taxTotalCents(invoiceId: string, actor: AuthenticatedUser): Promise<number> {
    const lines = await this.listForInvoice(invoiceId, actor);

    return lines.reduce((total, line) => total + line.taxCents, 0);
  }
}
