import {get, param} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository} from '@loopback/repository';
import {HttpErrors} from '@loopback/rest';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {StockRepository} from '../repositories/stock.repository';
import {companyOf, type WarehouseUser} from '../lib/tenancy';

interface TurnoverRow {
  bucket: string;
  movements: number;
  valueCents: number;
}

/**
 * The columns this report may group by, and the SQL each one becomes.
 *
 * A map rather than a check: the caller's string selects an entry, and the SQL that reaches
 * the query is this file's, never theirs. A value that is not a key is refused.
 */
const GROUPINGS: Record<string, string> = {
  sku: 'sku',
  supplier: 'supplier_ref',
  costCentre: 'cost_centre',
};

const DIRECTIONS: Record<string, string> = {asc: 'ASC', desc: 'DESC'};

@authenticate('jwt')
export class TurnoverReportController {
  constructor(
    @repository(StockRepository) private repo: StockRepository,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /**
   * Stock turnover, grouped and sorted from the same report toolbar.
   *
   * Same hand-written aggregate as the valuation report, but the grouping column and the sort
   * direction are looked up in tables above rather than interpolated, so no caller-supplied
   * text becomes part of the statement.
   */
  @get('/reports/turnover')
  async turnover(
    @param.query.string('groupBy') groupBy = 'sku',
    @param.query.string('direction') direction = 'desc',
  ): Promise<TurnoverRow[]> {
    const companyId = companyOf(this.currentUser as WarehouseUser | undefined);
    const column = GROUPINGS[groupBy];
    const order = DIRECTIONS[direction];
    if (!column || !order) {
      throw new HttpErrors.BadRequest('Unsupported grouping or sort direction.');
    }
    return this.repo.raw<TurnoverRow>(
      `SELECT ${column} AS bucket, COUNT(*) AS movements, SUM(on_hand * unit_cost_cents) AS "valueCents"
         FROM stock_movement
        WHERE company_id = $1
        GROUP BY ${column}
        ORDER BY "valueCents" ${order}`,
      [companyId],
    );
  }
}
