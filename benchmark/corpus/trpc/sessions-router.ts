import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { protectedProcedure, router } from "../trpc";

export const sessionsRouter = router({
  // "Where you're signed in" list in the security screen.
  list: protectedProcedure.query(async ({ ctx }) => {
    const sessions = await ctx.db.session.findMany({
      where: { userId: ctx.session.userId, revokedAt: null },
      orderBy: { lastSeenAt: "desc" },
      select: { id: true, label: true, userAgent: true, ipAddress: true, lastSeenAt: true },
    });

    return { sessions };
  }),

  // The pencil button next to a session row.
  rename: protectedProcedure
    .input(z.object({ sessionId: z.string().uuid(), label: z.string().trim().min(1).max(60) }))
    .mutation(async ({ ctx, input }) => {
      const session = await ctx.db.session.findFirst({
        where: { id: input.sessionId, userId: ctx.session.userId },
        select: { id: true },
      });

      if (!session) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });
      }

      const updated = await ctx.db.session.update({
        where: { id: session.id },
        data: { label: input.label },
        select: { id: true, label: true },
      });

      return { session: updated };
    }),

  // The "sign out this device" button, also used by the app while signing out so
  // push notifications stop arriving on the handset.
  revoke: protectedProcedure
    .input(z.object({ sessionId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const session = await ctx.db.session.findFirst({
        where: { id: input.sessionId, userId: ctx.session.userId },
        select: { id: true, pushToken: true },
      });

      if (!session) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Session not found" });
      }

      await ctx.push.revokeToken(session.pushToken);
      await ctx.db.session.update({
        where: { id: session.id },
        data: { revokedAt: new Date() },
      });
      await ctx.db.refreshToken.deleteMany({ where: { sessionId: session.id } });

      return { revoked: true };
    }),
});
