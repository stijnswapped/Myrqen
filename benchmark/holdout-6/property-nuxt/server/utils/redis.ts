import { createHash, randomBytes } from 'node:crypto'
import Redis from 'ioredis'

let client: Redis | undefined

export function useRedis(): Redis {
  if (!client) {
    const config = useRuntimeConfig()
    client = new Redis(config.redisUrl, {
      lazyConnect: false,
      maxRetriesPerRequest: 2,
      enableAutoPipelining: true,
    })
  }
  return client
}

export const SHARE_TTL_SECONDS = 900

export interface SharePayload {
  documentId: string
  tenancyId: string
  issuedBy: string
}

// Tokens are 43 base64url characters (32 bytes). Anything else is not one of
// ours and is rejected before we touch Redis.
const SHARE_TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/

function shareKey(token: string) {
  // Store the digest so a Redis dump does not hand out live links.
  return `share:${createHash('sha256').update(token).digest('hex')}`
}

/**
 * Mints a single-use share token for a statement or document and parks the
 * payload in Redis for fifteen minutes.
 */
export async function mintShareToken(payload: SharePayload): Promise<string> {
  const token = randomBytes(32).toString('base64url')
  await useRedis().set(shareKey(token), JSON.stringify(payload), 'EX', SHARE_TTL_SECONDS)
  return token
}

/** Redeems a share token exactly once. */
export async function consumeShareToken(candidate: string): Promise<SharePayload | null> {
  if (!SHARE_TOKEN_PATTERN.test(candidate)) return null

  const stored = await useRedis().getdel(shareKey(candidate))
  if (!stored) return null

  try {
    return JSON.parse(stored) as SharePayload
  } catch {
    return null
  }
}
