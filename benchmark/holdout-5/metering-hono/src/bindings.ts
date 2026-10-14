/**
 * Worker bindings and request-scoped types for the Tallymark metering service.
 *
 * D1 holds the durable ledger (accounts, customers, usage events, quotas).
 * KV holds the hot per-period counters that the ingest path reads on every call.
 * R2 holds generated usage exports and statements; they are served through
 * signed, account-scoped routes and the bucket itself is never public.
 */
export interface Env {
  DB: D1Database;
  COUNTERS: KVNamespace;
  EXPORTS: R2Bucket;
  /** Shared secret presented by platform-internal callers (billing runner, ops jobs). */
  INTERNAL_SERVICE_SECRET: string;
  /** Comma separated list of source addresses allowed to reach the internal router. */
  INTERNAL_ALLOWED_IPS: string;
  /** HMAC key used to sign statement download links. */
  EXPORT_LINK_SECRET: string;
  ENVIRONMENT: 'development' | 'staging' | 'production';
}

/**
 * A resolved API key.
 *
 * This is only ever built by the apiKeyAuth middleware from a row in `api_keys`.
 * Handlers must treat `accountId` as the tenant boundary: nothing in the request
 * body or path may widen it.
 */
export interface ApiKeyRecord {
  id: string;
  accountId: string;
  label: string;
  prefix: string;
  scopes: string[];
}

export interface AppEnv {
  Bindings: Env;
  Variables: {
    /** Present on every `/v1/*` request once apiKeyAuth has run. */
    apiKey?: ApiKeyRecord;
    /** Present on `/internal/*` requests once internalServiceAuth has run. */
    internalService?: string;
    requestId: string;
  };
}

/** Metrics the service knows how to meter. Anything else is rejected at ingest. */
export const KNOWN_METRICS = [
  'api_requests',
  'compute_seconds',
  'egress_bytes',
  'seats',
] as const;

export type KnownMetric = (typeof KNOWN_METRICS)[number];

export function isKnownMetric(value: unknown): value is KnownMetric {
  return typeof value === 'string' && (KNOWN_METRICS as readonly string[]).includes(value);
}

/** Billing periods are calendar months, `YYYY-MM`. */
export function currentPeriod(now = new Date()): string {
  const month = `${now.getUTCMonth() + 1}`.padStart(2, '0');
  return `${now.getUTCFullYear()}-${month}`;
}

export const PERIOD_PATTERN = /^\d{4}-(0[1-9]|1[0-2])$/;
