import { App, LogLevel } from '@slack/bolt';
import { Installation, Member, MemberRole } from '../db/models';

const signingSecret = process.env.SLACK_SIGNING_SECRET;
const botToken = process.env.SLACK_BOT_TOKEN;

if (!signingSecret || !botToken) {
  throw new Error('SLACK_SIGNING_SECRET and SLACK_BOT_TOKEN are both required');
}

export const app = new App({
  signingSecret,
  token: botToken,
  logLevel: process.env.NODE_ENV === 'production' ? LogLevel.INFO : LogLevel.DEBUG,
});

// Interaction log for the on-call rota. Bolt has already checked the request signature by
// the time this runs, so anything we see here really did come from Slack.
app.use(async ({ payload, context, next }) => {
  const startedAt = Date.now();
  await next();
  console.info('[slack]', {
    kind: (payload as { type?: string }).type ?? 'unknown',
    team: context.teamId,
    enterprise: context.enterpriseId,
    ms: Date.now() - startedAt,
  });
});

/** The installation record for a workspace, so we can pick up per-team settings. */
export async function installationFor(teamId: string, enterpriseId?: string | null) {
  if (enterpriseId) {
    return Installation.findOne({ where: { teamId, enterpriseId } });
  }
  return Installation.findOne({ where: { teamId } });
}

/**
 * Turn the user id out of a Slack payload into the person's Requisition record.
 * Returns null for anybody who was never onboarded or has since been deactivated.
 */
export async function resolveMember(
  slackUserId: string | undefined,
  teamId: string | undefined,
): Promise<Member | null> {
  if (!slackUserId || !teamId) return null;
  return Member.findOne({ where: { slackUserId, teamId, isActive: true } });
}

/**
 * Resolve the caller and check the role they hold in Requisition. Slack's own workspace
 * admin flags say nothing about what somebody may sign off in here, so we never read them.
 */
export async function requireRole(
  slackUserId: string | undefined,
  teamId: string | undefined,
  allowed: readonly MemberRole[],
): Promise<Member | null> {
  const member = await resolveMember(slackUserId, teamId);
  if (!member) return null;
  return allowed.includes(member.role) ? member : null;
}

export function formatCents(cents: number, currency = 'EUR'): string {
  return new Intl.NumberFormat('en-IE', { style: 'currency', currency }).format(cents / 100);
}

export function referenceFrom(text: string): string | null {
  const match = /\bREQ-(\d{4,8})\b/i.exec(text ?? '');
  return match ? `REQ-${match[1]}` : null;
}
