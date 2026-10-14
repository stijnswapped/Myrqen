import {get, post, param, requestBody} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository} from '@loopback/repository';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {StockRepository} from '../repositories/stock.repository';
import {companyOf, type WarehouseUser} from '../lib/tenancy';

interface IssueLine {
  sku: string;
  quantity: number;
}

/**
 * Goods issue — taking stock out for a shipment.
 *
 * Same arrangement as goods receipt, including an open health probe, so the routes are
 * decorated individually rather than at class level.
 */
export class GoodsIssueController {
  constructor(
    @repository(StockRepository) private repo: StockRepository,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /** Liveness for the load balancer. Deliberately open. */
  @get('/goods-issue/health')
  health(): {ok: true} {
    return {ok: true};
  }

  @authenticate('jwt')
  @get('/goods-issue/{id}')
  async read(@param.path.string('id') id: string): Promise<{id: string; lines: IssueLine[]}> {
    const companyId = companyOf(this.currentUser as WarehouseUser | undefined);
    const rows = await this.repo.raw<{lines: IssueLine[]}>(
      'SELECT lines FROM goods_issue WHERE id = $1 AND company_id = $2',
      [id, companyId],
    );
    return {id, lines: rows[0]?.lines ?? []};
  }

  /**
   * Issue stock for a shipment.
   *
   * Carries its own `@authenticate('jwt')`, and the decrement is matched on the caller's
   * company as well as the sku, so a write cannot reach another company's row even with a
   * valid token.
   */
  @authenticate('jwt')
  @post('/goods-issue/{id}/book')
  async book(
    @param.path.string('id') id: string,
    @requestBody() body: {lines: IssueLine[]},
  ): Promise<{booked: number}> {
    const companyId = companyOf(this.currentUser as WarehouseUser | undefined);
    let booked = 0;
    for (const line of body.lines ?? []) {
      await this.repo.raw(
        'UPDATE stock_item SET on_hand = on_hand - $3 WHERE sku = $1 AND company_id = $2',
        [line.sku, companyId, line.quantity],
      );
      booked += 1;
    }
    return {booked};
  }
}
