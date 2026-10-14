import {
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  Injectable,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import type { AuthenticatedRequest, BillingRole } from './jwt-auth.guard';

export const ROLES_METADATA_KEY = 'billing:required-roles';

/**
 * Declares the roles a handler needs. Only enforced where RolesGuard is
 * actually in the handler's guard chain.
 */
export const Roles = (...roles: BillingRole[]) => SetMetadata(ROLES_METADATA_KEY, roles);

@Injectable()
export class RolesGuard implements CanActivate {
  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const required = this.reflector.getAllAndOverride<BillingRole[] | undefined>(
      ROLES_METADATA_KEY,
      [context.getHandler(), context.getClass()],
    );

    if (!required || required.length === 0) {
      return true;
    }

    const { user } = context.switchToHttp().getRequest<AuthenticatedRequest>();

    if (!user) {
      throw new ForbiddenException('No billing identity on the request');
    }

    if (!required.some((role) => user.roles.includes(role))) {
      throw new ForbiddenException(`Requires one of: ${required.join(', ')}`);
    }

    return true;
  }
}
