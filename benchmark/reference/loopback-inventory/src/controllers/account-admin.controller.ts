import {patch, param, requestBody} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository} from '@loopback/repository';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {StockRepository} from '../repositories/stock.repository';
import {requireAdmin, type WarehouseUser} from '../lib/tenancy';

export interface AccountRecord {
  id: string;
  companyId: string;
  email: string;
  displayName: string;
  roles: string[];
  costCentre: string;
}

/**
 * Account administration for a company admin.
 */
@authenticate('jwt')
export class AccountAdminController {
  constructor(
    @repository(StockRepository) private repo: StockRepository,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /**
   * Update a colleague's account.
   *
   * Only an administrator reaches this, which is what the role check is for.
   */
  @patch('/accounts/{id}')
  async update(
    @param.path.string('id') id: string,
    @requestBody() changes: Partial<AccountRecord>,
  ): Promise<{updated: string}> {
    requireAdmin(this.currentUser as WarehouseUser | undefined);
    await this.repo.raw('UPDATE account SET data = data || $2 WHERE id = $1', [id, changes]);
    return {updated: id};
  }
}
