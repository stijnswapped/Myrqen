import {HttpErrors} from '@loopback/rest';
import type {Filter, Where} from '@loopback/repository';

/**
 * The caller LoopBack's authentication component resolved from the bearer token.
 *
 * Injected with `@inject(SecurityBindings.USER)`. It is the token's verified subject, never
 * a field from the request body or a header.
 */
export interface WarehouseUser {
  id: string;
  email: string;
  roles: string[];
  /** The operating company this account belongs to. Every stored row carries one. */
  companyId: string;
}

/** A caller with no company cannot be scoped, so no query is built for them. */
export function companyOf(user: WarehouseUser | undefined): string {
  if (!user) {
    throw new HttpErrors.Unauthorized('Authentication required.');
  }
  if (!user.companyId) {
    throw new HttpErrors.Forbidden('Your account is not attached to a company.');
  }
  return user.companyId;
}

/**
 * Pin a client-supplied filter to one company.
 *
 * The company clause is `and`-ed on top rather than merged into the caller's `where`, so a
 * caller cannot displace it by sending their own `companyId` — the two clauses both have to
 * hold. `include` is dropped: a relation traversal is a second query this function cannot
 * bound, and the controllers that need one ask for it explicitly.
 */
export function scopeFilter<T extends object>(
  filter: Filter<T> | undefined,
  companyId: string,
): Filter<T> {
  const callerWhere = filter?.where as Where<T> | undefined;
  const scoped: Where<T> = (callerWhere
    ? {and: [callerWhere, {companyId}]}
    : {companyId}) as Where<T>;
  const {include: _dropped, ...rest} = filter ?? {};
  return {...rest, where: scoped} as Filter<T>;
}

/** Roles permitted to administer another account's record. */
const ADMIN_ROLES = new Set(['company-admin', 'platform-admin']);

export function requireAdmin(user: WarehouseUser | undefined): WarehouseUser {
  if (!user) {
    throw new HttpErrors.Unauthorized('Authentication required.');
  }
  if (!user.roles.some(role => ADMIN_ROLES.has(role))) {
    throw new HttpErrors.Forbidden('Administrator role required.');
  }
  return user;
}
