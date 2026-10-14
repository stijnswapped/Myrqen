/**
 * Runtime configuration for the Gatefold ticketing API.
 *
 * Everything is read once at boot so a missing secret takes the container down
 * on start instead of failing the first request that happens to need it.
 */

function required(name: string): string {
  const value = Bun.env[name]

  if (value === undefined || value.trim() === '') {
    throw new Error(`Missing required environment variable: ${name}`)
  }

  return value.trim()
}

function numeric(name: string, fallback: number): number {
  const raw = Bun.env[name]

  if (raw === undefined || raw.trim() === '') {
    return fallback
  }

  const parsed = Number.parseInt(raw, 10)

  if (!Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(`Environment variable ${name} must be a positive integer`)
  }

  return parsed
}

export const env = {
  nodeEnv: Bun.env.NODE_ENV ?? 'development',
  port: numeric('PORT', 3000),
  databaseUrl: required('DATABASE_URL'),

  /** Signs the attendee/organiser session tokens issued by the accounts service. */
  sessionTokenSecret: required('SESSION_TOKEN_SECRET'),

  /** Signs the compact pass tokens that end up inside the ticket QR code. */
  gatePassSecret: required('GATE_PASS_SECRET'),

  /** Where the nightly payout statement generator writes its output tree. */
  statementDir: Bun.env.PAYOUT_STATEMENT_DIR ?? '/srv/gatefold/payout-statements',

  /** How long after the door time a pass still scans, in minutes. */
  gateGraceMinutes: numeric('GATE_GRACE_MINUTES', 45),

  /** Ceiling on a single self-service order. */
  maxTicketsPerOrder: numeric('MAX_TICKETS_PER_ORDER', 8),

  /** Refunds at or below this figure skip the support queue. */
  refundAutoApproveCents: numeric('REFUND_AUTO_APPROVE_CENTS', 5000),

  allowedOrigins: (Bun.env.ALLOWED_ORIGINS ?? 'https://gatefold.events').split(',').map((origin) => origin.trim()),
} as const

export type AppConfig = typeof env
