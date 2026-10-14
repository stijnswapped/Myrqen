import {get, param} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository, type Filter} from '@loopback/repository';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {StockRepository, type StockItem} from '../repositories/stock.repository';

/**
 * The stock browser behind the warehouse search screen.
 *
 * Every route is authenticated: the class-level decorator applies to all methods.
 */
@authenticate('jwt')
export class StockSearchController {
  constructor(
    @repository(StockRepository) private stockRepository: StockRepository,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /**
   * Search stock.
   *
   * The filter comes from LoopBack's own query parser, so the client can sort, page and
   * narrow exactly as the REST API documents.
   */
  @get('/stock/search')
  async search(
    @param.filter(Object, {name: 'filter'}) filter?: Filter<StockItem>,
  ): Promise<StockItem[]> {
    return this.stockRepository.find(filter);
  }
}
