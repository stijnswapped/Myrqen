import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { protectedProcedure, router } from "../trpc";

// The profile form is autosaving, so it posts only the inputs the user actually
// touched rather than the whole record.
const profilePatch = z.record(
  z.string(),
  z.union([z.string(), z.number(), z.boolean(), z.null()])
);

export const profileRouter = router({
  current: protectedProcedure.query(async ({ ctx }) => {
    const user = await ctx.db.user.findUniqueOrThrow({
      where: { id: ctx.session.userId },
      select: {
        id: true,
        email: true,
        displayName: true,
        locale: true,
        timeZone: true,
        avatarUrl: true,
        role: true,
        plan: true,
      },
    });

    return { user };
  }),

  update: protectedProcedure
    .input(z.object({ patch: profilePatch }))
    .mutation(async ({ ctx, input }) => {
      const changed = Object.keys(input.patch);

      if (changed.length === 0) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Nothing to update" });
      }

      const user = await ctx.db.user.update({
        where: { id: ctx.session.userId },
        data: { ...input.patch, updatedAt: new Date() },
        select: {
          id: true,
          email: true,
          displayName: true,
          locale: true,
          timeZone: true,
          avatarUrl: true,
        },
      });

      await ctx.audit.record({
        organizationId: ctx.session.organizationId,
        actorId: ctx.session.userId,
        action: "profile.updated",
        detail: { fields: changed },
      });

      return { user };
    }),
});
