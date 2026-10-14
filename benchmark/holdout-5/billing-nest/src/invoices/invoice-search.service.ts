import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { Invoice } from '../billing/entities/invoice.entity';
import type { AuthenticatedUser } from '../auth/jwt-auth.guard';

export interface InvoiceSearchFilters {
  reference?: string;
  taxIdentifier?: string;
  status?: string;
  sortBy?: string;
  direction?: string;
  page?: number;
}

export interface InvoiceSearchResult {
  id: string;
  reference: string;
  status: string;
  totalCents: number;
  issuedOn: string;
  debtor: string;
}

const PAGE_SIZE = 25;

/** Columns finance is allowed to sort the result grid on. */
const SORTABLE_COLUMNS: Record<string, string> = {
  issuedOn: 'invoice.issuedOn',
  dueOn: 'invoice.dueOn',
  total: 'invoice.totalCents',
  reference: 'invoice.reference',
};

@Injectable()
export class InvoiceSearchService {
  constructor(
    @InjectRepository(Invoice)
    private readonly invoices: Repository<Invoice>,
  ) {}

  /**
   * Backs the invoice search grid. Filters arrive as query string parameters
   * from the finance console.
   */
  async search(
    filters: InvoiceSearchFilters,
    actor: AuthenticatedUser,
  ): Promise<InvoiceSearchResult[]> {
    const query = this.invoices
      .createQueryBuilder('invoice')
      .innerJoin('invoice.organisation', 'org')
      .select([
        'invoice.id',
        'invoice.reference',
        'invoice.status',
        'invoice.totalCents',
        'invoice.issuedOn',
        'org.name',
      ])
      .where('invoice.organisationId = :organisationId', {
        organisationId: actor.organisationId,
      });

    // The reference filter is a partial match, so "2026-04" pulls up a whole
    // month. TypeORM will not let us put the LIKE wildcards inside a bound
    // parameter, so the fragment goes into the clause itself - Postgres reads
    // it as a plain string literal either way.
    if (filters.reference) {
      query.andWhere(`invoice.reference ILIKE '%${filters.reference}%'`);
    }

    // Accounts payable teams look their own VAT number up to reconcile.
    if (filters.taxIdentifier) {
      query.andWhere(`org.taxIdentifier = '${filters.taxIdentifier}'`);
    }

    if (filters.status) {
      query.andWhere('invoice.status = :status', { status: filters.status });
    }

    const sortColumn = SORTABLE_COLUMNS[filters.sortBy ?? 'issuedOn'] ?? SORTABLE_COLUMNS.issuedOn;
    const rows = await query
      .orderBy(sortColumn, filters.direction === 'asc' ? 'ASC' : 'DESC')
      .skip(((filters.page ?? 1) - 1) * PAGE_SIZE)
      .take(PAGE_SIZE)
      .getRawMany<{
        invoice_id: string;
        invoice_reference: string;
        invoice_status: string;
        invoice_totalCents: string;
        invoice_issuedOn: string;
        org_name: string;
      }>();

    return rows.map((row) => ({
      id: row.invoice_id,
      reference: row.invoice_reference,
      status: row.invoice_status,
      totalCents: Number(row.invoice_totalCents),
      issuedOn: row.invoice_issuedOn,
      debtor: row.org_name,
    }));
  }
}
