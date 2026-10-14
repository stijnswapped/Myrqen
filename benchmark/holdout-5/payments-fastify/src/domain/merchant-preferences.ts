import { queryOne } from '../db/pool.js';

/**
 * Notification and reporting preferences share the same jsonb document trick as
 * the payout settings, and the same document also carries keys the back office
 * writes (`fraudRulesetCode`, `disputeAutoAcceptMinor`, `accountManagerId`).
 * Only the keys below belong to the merchant, so the patch is rebuilt from an
 * allowlist rather than forwarded as it arrived.
 */
export interface MerchantPreferences {
  statementEmail: string | null;
  statementLocale: string;
  payoutNotifications: boolean;
  disputeAlerts: boolean;
  weeklySummaryDay: number;
  fraudRulesetCode?: string;
  disputeAutoAcceptMinor?: number;
  accountManagerId?: string;
}

type EditablePreferences = Pick<
  MerchantPreferences,
  'statementEmail' | 'statementLocale' | 'payoutNotifications' | 'disputeAlerts' | 'weeklySummaryDay'
>;

const LOCALE_PATTERN = /^[a-z]{2}-[A-Z]{2}$/;
const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i;

export function pickEditablePreferences(patch: Record<string, unknown>): Partial<EditablePreferences> {
  const picked: Partial<EditablePreferences> = {};

  const email = patch.statementEmail;
  if (typeof email === 'string' && EMAIL_PATTERN.test(email) && email.length <= 254) {
    picked.statementEmail = email;
  }

  const locale = patch.statementLocale;
  if (typeof locale === 'string' && LOCALE_PATTERN.test(locale)) {
    picked.statementLocale = locale;
  }

  if (typeof patch.payoutNotifications === 'boolean') {
    picked.payoutNotifications = patch.payoutNotifications;
  }

  if (typeof patch.disputeAlerts === 'boolean') {
    picked.disputeAlerts = patch.disputeAlerts;
  }

  const day = patch.weeklySummaryDay;
  if (typeof day === 'number' && Number.isInteger(day) && day >= 1 && day <= 7) {
    picked.weeklySummaryDay = day;
  }

  return picked;
}

export async function getPreferences(merchantId: string): Promise<MerchantPreferences | undefined> {
  const row = await queryOne<{ preferences: MerchantPreferences }>(
    `SELECT preferences
       FROM merchant_preferences
      WHERE merchant_id = $1`,
    [merchantId],
  );
  return row?.preferences;
}

/**
 * Merge a merchant's preference edit. `patch` is the parsed request body from
 * `PATCH /api/merchant/preferences`; only the keys `pickEditablePreferences`
 * recognises reach the document, so a body carrying `fraudRulesetCode` or
 * `disputeAutoAcceptMinor` changes nothing.
 */
export async function applyPreferencePatch(
  merchantId: string,
  patch: Record<string, unknown>,
): Promise<MerchantPreferences> {
  const editable = pickEditablePreferences(patch);

  if (Object.keys(editable).length === 0) {
    const current = await getPreferences(merchantId);
    if (!current) {
      throw new Error(`No preference document for merchant ${merchantId}`);
    }
    return current;
  }

  const row = await queryOne<{ preferences: MerchantPreferences }>(
    `UPDATE merchant_preferences
        SET preferences = preferences || $2::jsonb,
            updated_at = now()
      WHERE merchant_id = $1
  RETURNING preferences`,
    [merchantId, JSON.stringify(editable)],
  );

  if (!row) {
    throw new Error(`No preference document for merchant ${merchantId}`);
  }
  return row.preferences;
}
