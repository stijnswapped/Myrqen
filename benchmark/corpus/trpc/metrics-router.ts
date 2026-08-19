import { z } from "zod";

import { protectedProcedure, router } from "../trpc";

interface UsageRow {
  bucket: string;
  total_units: bigint;
  event_count: number;
}

// The breakdown dropdown offers three dimensions; the column names are not
// something Prisma can express as a parameter, so they come from this map.
const GROUP_COLUMNS: Record<string, string> = {
  feature: "feature_key",
  region: "region",
  plan: "plan_code",
};

export const metricsRouter = router({
  // Usage breakdown card on the operations dashboard.
  usageBreakdown: protectedProcedure
    .input(
      z.object({
        groupBy: z.enum(["feature", "region", "plan"]).default("feature"),
        since: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
        feature: z.string().max(40).optional(),
      })
    )
    .query(async ({ ctx, input }) => {
      const groupColumn = GROUP_COLUMNS[input.groupBy];
      const conditions = ["organization_id = $1", "recorded_at >= $2::date"];
      const values: unknown[] = [ctx.session.organizationId, input.since];

      if (input.feature) {
        values.push(input.feature);
        conditions.push(`feature_key = $${values.length}`);
      }

      const rows = await ctx.db.$queryRawUnsafe<UsageRow[]>(
        `SELECT ${groupColumn} AS bucket,
                sum(units)::bigint AS total_units,
                count(*)::int AS event_count
           FROM usage_events
          WHERE ${conditions.join(" AND ")}
          GROUP BY ${groupColumn}
          ORDER BY total_units DESC
          LIMIT 100`,
        ...values
      );

      return {
        groupBy: input.groupBy,
        buckets: rows.map((row) => ({
          bucket: row.bucket,
          totalUnits: Number(row.total_units),
          eventCount: row.event_count,
        })),
      };
    }),
});
