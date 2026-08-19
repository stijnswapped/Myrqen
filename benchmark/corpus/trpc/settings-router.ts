import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { protectedProcedure, router } from "../trpc";

// The settings form is autosaving, so it posts only the inputs the user actually
// touched rather than the whole record.
const settingsPatch = z
  .object({
    displayName: z.string().trim().min(1).max(80).optional(),
    locale: z.enum(["en", "nl", "de", "fr"]).optional(),
    timeZone: z.string().max(64).optional(),
    digestFrequency: z.enum(["daily", "weekly", "off"]).optional(),
  })
  .strict();

export const settingsRouter = router({
  current: protectedProcedure.query(async ({ ctx }) => {
    const user = await ctx.db.user.findUniqueOrThrow({
      where: { id: ctx.session.userId },
      select: {
        id: true,
        email: true,
        displayName: true,
        locale: true,
        timeZone: true,
        digestFrequency: true,
        role: true,
        plan: true,
      },
    });

    return { user };
  }),

  update: protectedProcedure
    .input(z.object({ patch: settingsPatch }))
    .mutation(async ({ ctx, input }) => {
      const { displayName, locale, timeZone, digestFrequency } = input.patch;
      const changed = Object.keys(input.patch);

      if (changed.length === 0) {
        throw new TRPCError({ code: "BAD_REQUEST", message: "Nothing to update" });
      }

      const user = await ctx.db.user.update({
        where: { id: ctx.session.userId },
        data: {
          ...(displayName !== undefined ? { displayName } : {}),
          ...(locale !== undefined ? { locale } : {}),
          ...(timeZone !== undefined ? { timeZone } : {}),
          ...(digestFrequency !== undefined ? { digestFrequency } : {}),
          updatedAt: new Date(),
        },
        select: {
          id: true,
          email: true,
          displayName: true,
          locale: true,
          timeZone: true,
          digestFrequency: true,
        },
      });

      await ctx.audit.record({
        organizationId: ctx.session.organizationId,
        actorId: ctx.session.userId,
        action: "settings.updated",
        detail: { fields: changed },
      });

      return { user };
    }),
});
