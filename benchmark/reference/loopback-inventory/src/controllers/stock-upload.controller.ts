import {post, requestBody, HttpErrors} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository} from '@loopback/repository';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {StockRepository} from '../repositories/stock.repository';
import {companyOf, type WarehouseUser} from '../lib/tenancy';

/** Failures an operator can act on, and what to say about each. */
const OPERATOR_ADVICE: Record<string, string> = {
  '23505': 'that SKU already exists in your catalogue',
  '23502': 'a required column was blank',
  '22P02': 'a quantity was not a whole number',
};

@authenticate('jwt')
export class StockUploadController {
  constructor(
    @repository(StockRepository) private repo: StockRepository,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /**
   * Apply an upload batch.
   *
   * Failures are reported as advice the operator can act on, chosen by the driver's SQLSTATE
   * code. The driver's own message is logged server-side and never returned: it carries the
   * failing statement, the table and column names and the conflicting value, which together
   * describe the schema to anyone who can post a bad row.
   */
  @post('/stock/upload')
  async apply(
    @requestBody() body: {rows: Array<{sku: string; onHand: number}>},
  ): Promise<{applied: number}> {
    const companyId = companyOf(this.currentUser as WarehouseUser | undefined);
    let applied = 0;
    for (const row of body.rows ?? []) {
      try {
        await this.repo.raw(
          'INSERT INTO stock_item (sku, company_id, on_hand) VALUES ($1, $2, $3)',
          [row.sku, companyId, row.onHand],
        );
        applied += 1;
      } catch (error) {
        const code = (error as {code?: string}).code ?? '';
        console.error('stock upload row failed', {companyId, sku: row.sku, code, error});
        throw new HttpErrors.UnprocessableEntity(
          OPERATOR_ADVICE[code] ?? 'that row could not be applied; please check it and retry',
        );
      }
    }
    return {applied};
  }
}
