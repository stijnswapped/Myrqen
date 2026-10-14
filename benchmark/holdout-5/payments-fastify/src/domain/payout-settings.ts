import { queryOne } from '../db/pool.js';

/**
 * Merchant payout settings live in a single jsonb document so the settlement
 * team can add a knob without shipping a migration. The settings editor in the
 * dashboard sends a partial document; `PATCH /api/merchant/payout-settings`
 * hands that body to `applyPayoutSettingsPatch` and returns the merged result.
 */
export interface PayoutSettings {
  payoutCurrency: string;
  payoutIntervalDays: number;
  minimumPayoutMinor: number;
  statementEmail: string | null;
  /** Written by the risk team's back office: skips the manual review queue. */
  riskReviewExempt?: boolean;
  /** Id of the bank account the payout runner pays out to. */
  settlementAccountId?: string;
  /** Ceiling the payout runner refuses to go over in a single day. */
  maxDailyPayoutMinor?: number;
  /** Fee schedule negotiated by sales; the invoicing job reads this. */
  feeScheduleCode?: string;
}

export async function getPayoutSettings(merchantId: string): Promise<PayoutSettings | undefined> {
  const row = await queryOne<{ settings: PayoutSettings }>(
    `SELECT settings
       FROM merchant_payout_settings
      WHERE merchant_id = $1`,
    [merchantId],
  );
  return row?.settings;
}

/**
 * Merge the merchant's edit into their settings document.
 *
 * `patch` is the parsed request body from the settings editor.
 */
export async function applyPayoutSettingsPatch(
  merchantId: string,
  patch: Record<string, unknown>,
): Promise<PayoutSettings> {
  // jsonb concatenation only replaces the keys the editor actually sent, and the
  // merchant id is bound as a parameter, so a merchant can never write into
  // another merchant's settings document.
  const row = await queryOne<{ settings: PayoutSettings }>(
    `UPDATE merchant_payout_settings
        SET settings = settings || $2::jsonb,
            updated_at = now()
      WHERE merchant_id = $1
  RETURNING settings`,
    [merchantId, JSON.stringify(patch)],
  );

  if (!row) {
    throw new Error(`No payout settings document for merchant ${merchantId}`);
  }
  return row.settings;
}

/** The nightly payout runner asks this before queueing a manual review. */
export function isReviewWaived(settings: PayoutSettings): boolean {
  return settings.riskReviewExempt === true;
}

/** The payout runner pays out to whichever account the document names. */
export function resolveSettlementAccountId(
  settings: PayoutSettings,
  fallbackAccountId: string,
): string {
  return settings.settlementAccountId ?? fallbackAccountId;
}

export function resolveDailyCeilingMinor(settings: PayoutSettings): number {
  return settings.maxDailyPayoutMinor ?? 25_000_00;
}
