import { test } from "node:test";
import assert from "node:assert/strict";
import {
  FREE_SYNC_LIMITS,
  describeQuotaBlock,
  evaluateQuota,
  expiresAtFromSync,
  quotaDayKey,
  quotaDayWindow,
  quotaWeekKey,
  quotaWeekWindow
} from "../dist/index.js";

const iso = (s) => new Date(s);

test("quota day window is anchored at 06:00 UTC", () => {
  const before = quotaDayWindow(iso("2026-08-18T05:59:59.999Z"));
  assert.equal(before.start.toISOString(), "2026-08-17T06:00:00.000Z");
  assert.equal(before.end.toISOString(), "2026-08-18T06:00:00.000Z");

  const exactly = quotaDayWindow(iso("2026-08-18T06:00:00.000Z"));
  assert.equal(exactly.start.toISOString(), "2026-08-18T06:00:00.000Z");
  assert.equal(exactly.end.toISOString(), "2026-08-19T06:00:00.000Z");

  const after = quotaDayWindow(iso("2026-08-18T06:00:00.001Z"));
  assert.equal(after.start.toISOString(), "2026-08-18T06:00:00.000Z");
});

test("a scan at 05:59 and one at 06:01 fall in different quota days", () => {
  assert.notEqual(quotaDayKey(iso("2026-08-18T05:59:00Z")), quotaDayKey(iso("2026-08-18T06:01:00Z")));
  assert.equal(quotaDayKey(iso("2026-08-18T06:01:00Z")), quotaDayKey(iso("2026-08-19T05:00:00Z")));
});

test("quota week window is anchored Monday 06:00 UTC", () => {
  const week = quotaWeekWindow(iso("2026-08-18T12:00:00Z"));
  assert.equal(week.start.toISOString(), "2026-08-17T06:00:00.000Z");
  assert.equal(week.end.toISOString(), "2026-08-24T06:00:00.000Z");
  assert.equal(week.start.getUTCDay(), 1, "week starts on Monday");
});

test("Monday 05:59 UTC still belongs to the previous quota week", () => {
  const before = quotaWeekWindow(iso("2026-08-17T05:59:00Z"));
  assert.equal(before.start.toISOString(), "2026-08-10T06:00:00.000Z");
  const after = quotaWeekWindow(iso("2026-08-17T06:00:00Z"));
  assert.equal(after.start.toISOString(), "2026-08-17T06:00:00.000Z");
  assert.notEqual(quotaWeekKey(iso("2026-08-17T05:59:00Z")), quotaWeekKey(iso("2026-08-17T06:00:00Z")));
});

test("free limits are 5 per day and 15 per week with 21-day retention", () => {
  assert.equal(FREE_SYNC_LIMITS.daily, 5);
  assert.equal(FREE_SYNC_LIMITS.weekly, 15);
  assert.equal(FREE_SYNC_LIMITS.retentionDays, 21);
});

test("daily boundary blocks at the fifth report", () => {
  const at = iso("2026-08-18T12:00:00Z");
  const base = { plan: "free", limits: FREE_SYNC_LIMITS, weeklyUsed: 5, at };
  assert.equal(evaluateQuota({ ...base, dailyUsed: 4 }).eligible, true);
  const blocked = evaluateQuota({ ...base, dailyUsed: 5 });
  assert.equal(blocked.eligible, false);
  assert.equal(blocked.blockedBy, "daily");
  assert.equal(blocked.daily.resetsAt, "2026-08-19T06:00:00.000Z");
});

test("weekly cap blocks even when the day is fresh", () => {
  const at = iso("2026-08-20T07:00:00Z");
  const blocked = evaluateQuota({ plan: "free", limits: FREE_SYNC_LIMITS, dailyUsed: 0, weeklyUsed: 15, at });
  assert.equal(blocked.eligible, false);
  assert.equal(blocked.blockedBy, "weekly");
  assert.equal(blocked.weekly.resetsAt, "2026-08-24T06:00:00.000Z");
});

test("whichever cap is reached first blocks", () => {
  const at = iso("2026-08-18T12:00:00Z");
  const both = evaluateQuota({ plan: "free", limits: FREE_SYNC_LIMITS, dailyUsed: 5, weeklyUsed: 15, at });
  assert.equal(both.blockedBy, "both");
});

test("limit copy is concise, names the reset, and offers manual sync", () => {
  const quota = evaluateQuota({
    plan: "free",
    limits: FREE_SYNC_LIMITS,
    dailyUsed: 0,
    weeklyUsed: 15,
    at: iso("2026-08-20T07:00:00Z")
  });
  const message = describeQuotaBlock(quota, "myrqen", "rpt_abc");
  assert.match(message, /stay local/);
  assert.match(message, /Monday 06:00 UTC/);
  assert.match(message, /myrqen sync rpt_abc/);
  assert.ok(!/\?/.test(message), "must not ask a question that cannot succeed");
});

test("free retention expiry is exactly 21 days after successful sync", () => {
  const synced = iso("2026-08-18T09:15:00Z");
  assert.equal(expiresAtFromSync(synced, 21).toISOString(), "2026-09-08T09:15:00.000Z");
});
