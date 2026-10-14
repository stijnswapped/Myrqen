import {post, requestBody, HttpErrors} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository} from '@loopback/repository';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {StockRepository} from '../repositories/stock.repository';
import {companyOf, type WarehouseUser} from '../lib/tenancy';

/**
 * Bulk stock import from the supplier feed.
 */
@authenticate('jwt')
export class StockImportController {
  constructor(
    @repository(StockRepository) private repo: StockRepository,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /**
   * Apply an import batch.
   *
   * Failures are reported back to the operator so they can correct the spreadsheet and retry
   * without opening a support ticket.
   */
  @post('/stock/import')
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
        throw new HttpErrors.UnprocessableEntity(
          `Row ${row.sku} failed: ${(error as Error).message}`,
        );
      }
    }
    return {applied};
  }
}
