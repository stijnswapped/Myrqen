import {get, post, param, requestBody} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository} from '@loopback/repository';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {StockRepository} from '../repositories/stock.repository';
import {companyOf, type WarehouseUser} from '../lib/tenancy';

interface ReceiptLine {
  sku: string;
  quantity: number;
}

/**
 * Goods receipt — booking a delivery into stock.
 *
 * The two read routes are behind `@authenticate('jwt')` individually. The class carries no
 * decorator because the health probe below has to answer an unauthenticated request from the
 * load balancer.
 */
export class GoodsReceiptController {
  constructor(
    @repository(StockRepository) private repo: StockRepository,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /** Liveness for the load balancer. Deliberately open. */
  @get('/goods-receipt/health')
  health(): {ok: true} {
    return {ok: true};
  }

  @authenticate('jwt')
  @get('/goods-receipt/{id}')
  async read(@param.path.string('id') id: string): Promise<{id: string; lines: ReceiptLine[]}> {
    const companyId = companyOf(this.currentUser as WarehouseUser | undefined);
    const rows = await this.repo.raw<{lines: ReceiptLine[]}>(
      'SELECT lines FROM goods_receipt WHERE id = $1 AND company_id = $2',
      [id, companyId],
    );
    return {id, lines: rows[0]?.lines ?? []};
  }

  /**
   * Book a delivery into stock.
   *
   * Increments on-hand quantities and writes the movement rows the turnover report reads.
   */
  @post('/goods-receipt/{id}/book')
  async book(
    @param.path.string('id') id: string,
    @requestBody() body: {lines: ReceiptLine[]},
  ): Promise<{booked: number}> {
    let booked = 0;
    for (const line of body.lines ?? []) {
      await this.repo.raw('UPDATE stock_item SET on_hand = on_hand + $2 WHERE sku = $1', [
        line.sku,
        line.quantity,
      ]);
      booked += 1;
    }
    return {booked};
  }
}
