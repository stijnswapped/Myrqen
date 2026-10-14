import {patch, param, requestBody} from '@loopback/rest';
import {authenticate} from '@loopback/authentication';
import {inject} from '@loopback/core';
import {repository} from '@loopback/repository';
import {SecurityBindings, type UserProfile} from '@loopback/security';

import {StockRepository} from '../repositories/stock.repository';
import {companyOf, requireAdmin, type WarehouseUser} from '../lib/tenancy';

export interface ProfileRecord {
  id: string;
  companyId: string;
  email: string;
  displayName: string;
  roles: string[];
  costCentre: string;
}

/** The fields an administrator may change. `roles` and `companyId` are not among them. */
const ADMINISTRABLE = ['displayName', 'costCentre'] as const;

function onlyAdministrable(changes: Partial<ProfileRecord>): Partial<ProfileRecord> {
  const out: Partial<ProfileRecord> = {};
  for (const field of ADMINISTRABLE) {
    if (Object.prototype.hasOwnProperty.call(changes, field)) {
      out[field] = changes[field];
    }
  }
  return out;
}

@authenticate('jwt')
export class ProfileAdminController {
  constructor(
    @repository(StockRepository) private repo: StockRepository,
    @inject(SecurityBindings.USER, {optional: true}) private currentUser?: UserProfile,
  ) {}

  /**
   * Update a colleague's profile.
   *
   * The payload is reduced to the two administrable fields before it reaches the database, so
   * an administrator cannot grant themselves or anyone else a role, and cannot move an
   * account into another company. The row is also matched on the administrator's own company,
   * so the id has to belong to it.
   */
  @patch('/profiles/{id}')
  async update(
    @param.path.string('id') id: string,
    @requestBody() changes: Partial<ProfileRecord>,
  ): Promise<{updated: string}> {
    const admin = requireAdmin(this.currentUser as WarehouseUser | undefined);
    const companyId = companyOf(admin);
    await this.repo.raw('UPDATE profile SET data = data || $3 WHERE id = $1 AND company_id = $2', [
      id,
      companyId,
      onlyAdministrable(changes),
    ]);
    return {updated: id};
  }
}
