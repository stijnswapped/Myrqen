import type { PlanId, SyncQuota } from "@myrqen/contracts";

const HOUR_MS = 60 * 60 * 1000;
const DAY_MS = 24 * HOUR_MS;
const WEEK_MS = 7 * DAY_MS;

/** Quota boundaries are UTC-anchored. Never derived from user locale or DST. */
export const RESET_HOUR_UTC = 6;

export interface QuotaWindow {
  start: Date;
  end: Date;
  key: string;
}

function pad(value: number): string {
  return value < 10 ? `0${value}` : String(value);
}

/** The quota day runs 06:00:00 UTC to 06:00:00 UTC. */
export function quotaDayWindow(at: Date = new Date()): QuotaWindow {
  const shifted = at.getTime() - RESET_HOUR_UTC * HOUR_MS;
  const dayIndex = Math.floor(shifted / DAY_MS);
  const start = new Date(dayIndex * DAY_MS + RESET_HOUR_UTC * HOUR_MS);
  const end = new Date(start.getTime() + DAY_MS);
  const key = `${start.getUTCFullYear()}-${pad(start.getUTCMonth() + 1)}-${pad(start.getUTCDate())}`;
  return { start, end, key };
}

/** The quota week runs Monday 06:00:00 UTC to Monday 06:00:00 UTC. */
export function quotaWeekWindow(at: Date = new Date()): QuotaWindow {
  const day = quotaDayWindow(at).start;
  const daysSinceMonday = (day.getUTCDay() + 6) % 7;
  const start = new Date(day.getTime() - daysSinceMonday * DAY_MS);
  const end = new Date(start.getTime() + WEEK_MS);
  const key = `${start.getUTCFullYear()}-${pad(start.getUTCMonth() + 1)}-${pad(start.getUTCDate())}`;
  return { start, end, key };
}

export function quotaDayKey(at: Date = new Date()): string {
  return quotaDayWindow(at).key;
}

export function quotaWeekKey(at: Date = new Date()): string {
  return quotaWeekWindow(at).key;
}

export interface PlanQuotaLimits {
  daily: number;
  weekly: number;
  retentionDays: number;
}

export const FREE_SYNC_LIMITS: PlanQuotaLimits = Object.freeze({
  daily: 5,
  weekly: 15,
  retentionDays: 21
});

export function evaluateQuota(input: {
  plan: PlanId;
  limits: PlanQuotaLimits;
  dailyUsed: number;
  weeklyUsed: number;
  at?: Date;
}): SyncQuota {
  const at = input.at ?? new Date();
  const day = quotaDayWindow(at);
  const week = quotaWeekWindow(at);
  const dailyBlocked = input.dailyUsed >= input.limits.daily;
  const weeklyBlocked = input.weeklyUsed >= input.limits.weekly;

  const quota: SyncQuota = {
    eligible: !dailyBlocked && !weeklyBlocked,
    daily: { used: input.dailyUsed, limit: input.limits.daily, resetsAt: day.end.toISOString() },
    weekly: { used: input.weeklyUsed, limit: input.limits.weekly, resetsAt: week.end.toISOString() },
    retentionDays: input.limits.retentionDays,
    plan: input.plan
  };
  if (dailyBlocked && weeklyBlocked) quota.blockedBy = "both";
  else if (dailyBlocked) quota.blockedBy = "daily";
  else if (weeklyBlocked) quota.blockedBy = "weekly";
  return quota;
}

/** Concise, non-alarming limit copy. Never asks a question that cannot succeed. */
export function describeQuotaBlock(quota: SyncQuota, cliName: string, localReportId?: string): string {
  const resetsAt = quota.blockedBy === "weekly" ? quota.weekly.resetsAt : quota.daily.resetsAt;
  const which = quota.blockedBy === "weekly" ? "weekly" : "daily";
  const retry = localReportId ? ` You can run "${cliName} sync ${localReportId}" after that.` : "";
  return `Cloud report limit reached (${which}). This scan will stay local. Limit resets ${formatInstant(resetsAt)}.${retry}`;
}

export function expiresAtFromSync(syncCreatedAt: Date, retentionDays: number): Date {
  return new Date(syncCreatedAt.getTime() + retentionDays * DAY_MS);
}

export function formatInstant(iso: string): string {
  const date = new Date(iso);
  const weekday = ["Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"][date.getUTCDay()];
  return `${weekday} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())} UTC`;
}
