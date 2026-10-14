import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { DunningCase } from '../billing/entities/dunning-case.entity';
import type { AuthenticatedUser } from '../auth/jwt-auth.guard';

export interface DunningSearchFilters {
  debtor?: string;
  stage?: string;
  sortBy?: string;
  direction?: string;
  page?: number;
}

export interface DunningCaseRow {
  id: string;
  invoiceReference: string;
  debtorName: string;
  stage: string;
  overdueCents: number;
  nextActionOn: string;
}

const PAGE_SIZE = 25;

/** Columns the collections grid may be sorted on. */
const SORTABLE_COLUMNS: Record<string, string> = {
  nextActionOn: 'dunning.nextActionOn',
  overdue: 'dunning.overdueCents',
  debtor: 'dunning.debtorName',
};

@Injectable()
export class DunningSearchService {
  constructor(
    @InjectRepository(DunningCase)
    private readonly cases: Repository<DunningCase>,
  ) {}

  /**
   * Backs the collections work queue. Same free text filter as the invoice
   * grid, so collections can type part of a debtor name.
   */
  async search(
    filters: DunningSearchFilters,
    actor: AuthenticatedUser,
  ): Promise<DunningCaseRow[]> {
    const query = this.cases
      .createQueryBuilder('dunning')
      .where('dunning.organisationId = :organisationId', {
        organisationId: actor.organisationId,
      });

    // The wildcards live in the parameter value, not in the clause, so the
    // fragment the user typed never becomes part of the statement text.
    if (filters.debtor) {
      query.andWhere('dunning.debtorName ILIKE :debtor', {
        debtor: `%${filters.debtor}%`,
      });
    }

    if (filters.stage) {
      query.andWhere('dunning.stage = :stage', { stage: filters.stage });
    }

    const sortColumn = SORTABLE_COLUMNS[filters.sortBy ?? 'nextActionOn'] ?? SORTABLE_COLUMNS.nextActionOn;
    const rows = await query
      .orderBy(sortColumn, filters.direction === 'asc' ? 'ASC' : 'DESC')
      .skip(((filters.page ?? 1) - 1) * PAGE_SIZE)
      .take(PAGE_SIZE)
      .getMany();

    return rows.map((dunningCase) => ({
      id: dunningCase.id,
      invoiceReference: dunningCase.invoiceReference,
      debtorName: dunningCase.debtorName,
      stage: dunningCase.stage,
      overdueCents: dunningCase.overdueCents,
      nextActionOn: dunningCase.nextActionOn,
    }));
  }
}
