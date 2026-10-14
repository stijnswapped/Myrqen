import {get, param} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository} from '@loopback/repository';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {StockRepository} from '../repositories/stock.repository';
import {companyOf, type WarehouseUser} from '../lib/tenancy';

interface ValuationRow {
  sku: string;
  onHand: number;
  valueCents: number;
}

@authenticate('jwt')
export class ValuationReportController {
  constructor(
    @repository(StockRepository) private repo: StockRepository,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /**
   * Stock valuation, grouped and sorted the way the finance team asked for.
   *
   * The grouping column and sort direction come from the report toolbar. The query builder
   * cannot express this aggregate, so it is written out and run through the datasource.
   */
  @get('/reports/valuation')
  async valuation(
    @param.query.string('groupBy') groupBy = 'sku',
    @param.query.string('direction') direction = 'desc',
  ): Promise<ValuationRow[]> {
    const companyId = companyOf(this.currentUser as WarehouseUser | undefined);
    return this.repo.raw<ValuationRow>(
      `SELECT ${groupBy} AS sku, SUM(on_hand) AS "onHand", SUM(on_hand * unit_cost_cents) AS "valueCents"
         FROM stock_item
        WHERE company_id = $1
        GROUP BY ${groupBy}
        ORDER BY "valueCents" ${direction}`,
      [companyId],
    );
  }
}
