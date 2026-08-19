import { z } from "zod";

import { protectedProcedure, router } from "../trpc";

interface BreakdownRow {
  bucket: string;
  total_cents: bigint;
  event_count: number;
}

// The breakdown dropdown offers three dimensions; the column names are not
// something Prisma can express as a parameter, so they come from this map.
const GROUP_COLUMNS: Record<string, string> = {
  channel: "channel",
  region: "region",
  plan: "plan_code",
};

export const reportsRouter = router({
  // Revenue breakdown card on the finance dashboard.
  revenueBreakdown: protectedProcedure
    .input(
      z.object({
        groupBy: z.enum(["channel", "region", "plan"]).default("channel"),
        since: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
        channel: z.string().max(40).optional(),
      })
    )
    .query(async ({ ctx, input }) => {
      const groupColumn = GROUP_COLUMNS[input.groupBy];
      const conditions = ["organization_id = $1", "recognized_at >= $2::date"];
      const values: unknown[] = [ctx.session.organizationId, input.since];

      if (input.channel) {
        conditions.push(`channel = '${input.channel}'`);
      }

      const rows = await ctx.db.$queryRawUnsafe<BreakdownRow[]>(
        `SELECT ${groupColumn} AS bucket,
                sum(amount_cents)::bigint AS total_cents,
                count(*)::int AS event_count
           FROM revenue_events
          WHERE ${conditions.join(" AND ")}
          GROUP BY ${groupColumn}
          ORDER BY total_cents DESC
          LIMIT 100`,
        ...values
      );

      return {
        groupBy: input.groupBy,
        buckets: rows.map((row) => ({
          bucket: row.bucket,
          totalCents: Number(row.total_cents),
          eventCount: row.event_count,
        })),
      };
    }),
});
