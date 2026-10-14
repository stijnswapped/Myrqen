import {
  CanActivate,
  ExecutionContext,
  Injectable,
  UnauthorizedException,
  createParamDecorator,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import type { Request } from 'express';

export type BillingRole = 'billing_viewer' | 'billing_operator' | 'billing_admin';

/** Shape of `request.user` on every authenticated billing request. */
export interface AuthenticatedUser {
  readonly id: string;
  readonly email: string;
  readonly organisationId: string;
  readonly roles: readonly BillingRole[];
}

export interface AuthenticatedRequest extends Request {
  user?: AuthenticatedUser;
}

interface BillingTokenClaims {
  sub: string;
  email: string;
  org: string;
  roles?: BillingRole[];
}

/**
 * Verifies the bearer token issued by the identity service and hangs the
 * resolved billing identity on the request. Every controller in this service
 * sits behind it.
 */
@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly jwtService: JwtService) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const token = readBearerToken(request);

    if (!token) {
      throw new UnauthorizedException('Missing bearer token');
    }

    try {
      const claims = await this.jwtService.verifyAsync<BillingTokenClaims>(token);

      request.user = {
        id: claims.sub,
        email: claims.email,
        organisationId: claims.org,
        roles: claims.roles ?? ['billing_viewer'],
      };

      return true;
    } catch {
      // Deliberately opaque: the caller does not get to learn whether the
      // token was expired, malformed or signed with the wrong key.
      throw new UnauthorizedException('Invalid bearer token');
    }
  }
}

function readBearerToken(request: AuthenticatedRequest): string | null {
  const header = request.headers.authorization;
  if (!header) {
    return null;
  }

  const [scheme, value] = header.split(' ');
  if (scheme?.toLowerCase() !== 'bearer' || !value) {
    return null;
  }

  return value.trim();
}

/** `@CurrentUser()` — the identity JwtAuthGuard attached to the request. */
export const CurrentUser = createParamDecorator(
  (_data: unknown, context: ExecutionContext): AuthenticatedUser => {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();

    if (!request.user) {
      throw new UnauthorizedException('Handler reached without an identity');
    }

    return request.user;
  },
);
