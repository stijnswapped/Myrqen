import {get, param} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository, type Filter} from '@loopback/repository';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {StockRepository, type StockItem} from '../repositories/stock.repository';
import {companyOf, scopeFilter, type WarehouseUser} from '../lib/tenancy';

/**
 * The catalogue browser behind the purchasing screen.
 *
 * Same class-level authentication as the stock browser.
 */
@authenticate('jwt')
export class CatalogueSearchController {
  constructor(
    @repository(StockRepository) private stockRepository: StockRepository,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /**
   * Search the catalogue.
   *
   * The client-supplied filter is kept — sorting and paging are the feature — but pinned to
   * the caller's company by `scopeFilter`, which `and`-s the company clause on top so a
   * caller cannot displace it by sending their own `companyId`.
   */
  @get('/catalogue/search')
  async search(
    @param.filter(Object, {name: 'filter'}) filter?: Filter<StockItem>,
  ): Promise<StockItem[]> {
    const companyId = companyOf(this.currentUser as WarehouseUser | undefined);
    return this.stockRepository.find(scopeFilter(filter, companyId));
  }
}
