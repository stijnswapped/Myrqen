import { GetCommand } from '@aws-sdk/lib-dynamodb';
import { documentClient, tables } from '../config/environment.js';

export type SupportRole = 'support_agent' | 'support_lead' | 'billing_admin';

export interface CallerSession {
  token: string;
  accountId: string;
  role: SupportRole;
  displayName: string;
  /** Unix seconds. */
  expiresAt: number;
}

/**
 * What the tool implementations know about whoever is driving them.
 *
 * `session` is null when this process speaks MCP over stdio: it was started by
 * a human on their own workstation, it runs with that human's own AWS
 * credentials, and there is no second party to identify. Over the HTTP
 * transport there is one, and it is always non-null there.
 */
export interface ToolContext {
  session: CallerSession | null;
}

/** Resolve a bearer token into the session row the auth service wrote. */
export async function lookupSession(token: string): Promise<CallerSession | null> {
  const result = await documentClient.send(
    new GetCommand({
      TableName: tables.mcpSessions,
      Key: { token },
      ProjectionExpression: 'token, accountId, #role, displayName, expiresAt',
      ExpressionAttributeNames: { '#role': 'role' },
    }),
  );

  const session = result.Item as CallerSession | undefined;
  if (!session) {
    return null;
  }
  if (session.expiresAt <= Math.floor(Date.now() / 1000)) {
    return null;
  }
  return session;
}

/**
 * Which account a tool call is allowed to touch.
 *
 * When there is a session it is authoritative - a caller supplied accountId is
 * only ever a hint, and it can never widen the scope. Over stdio there is no
 * session, so the operator has to say which account they are working on.
 */
export function accountScope(ctx: ToolContext, requestedAccountId?: string): string {
  if (ctx.session) {
    return ctx.session.accountId;
  }
  if (!requestedAccountId) {
    throw new Error('accountId is required when the server is driven over stdio');
  }
  return requestedAccountId;
}

export interface RoleDecision {
  ok: boolean;
  message?: string;
}

/**
 * Role gate for the tools that change money or entitlements. A stdio caller is
 * the operator themselves, so there is no role to check - they already have the
 * credentials this process runs with.
 */
export function requireRole(ctx: ToolContext, ...allowed: SupportRole[]): RoleDecision {
  if (!ctx.session) {
    return { ok: true };
  }
  if (allowed.includes(ctx.session.role)) {
    return { ok: true };
  }
  return {
    ok: false,
    message: `This action is limited to ${allowed.join(' or ')}; this session is ${ctx.session.role}.`,
  };
}
