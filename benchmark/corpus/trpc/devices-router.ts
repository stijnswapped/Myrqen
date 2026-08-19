import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { protectedProcedure, publicProcedure, router } from "../trpc";

export const devicesRouter = router({
  // "Your devices" list in the account screen.
  list: protectedProcedure.query(async ({ ctx }) => {
    const devices = await ctx.db.device.findMany({
      where: { userId: ctx.session.userId },
      orderBy: { lastSeenAt: "desc" },
      select: { id: true, label: true, platform: true, lastSeenAt: true },
    });

    return { devices };
  }),

  // The pencil button next to a device row.
  rename: protectedProcedure
    .input(z.object({ deviceId: z.string().uuid(), label: z.string().trim().min(1).max(60) }))
    .mutation(async ({ ctx, input }) => {
      const device = await ctx.db.device.findFirst({
        where: { id: input.deviceId, userId: ctx.session.userId },
        select: { id: true },
      });

      if (!device) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Device not found" });
      }

      const updated = await ctx.db.device.update({
        where: { id: device.id },
        data: { label: input.label },
        select: { id: true, label: true },
      });

      return { device: updated };
    }),

  // The mobile app calls this while signing out, once it has already dropped its
  // local session, so push notifications stop arriving on the handset.
  deregister: publicProcedure
    .input(z.object({ deviceId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      const device = await ctx.db.device.findUnique({
        where: { id: input.deviceId },
        select: { id: true, userId: true, pushToken: true },
      });

      if (!device) {
        return { deregistered: false };
      }

      await ctx.push.revokeToken(device.pushToken);
      await ctx.db.device.delete({ where: { id: device.id } });
      await ctx.db.refreshToken.deleteMany({ where: { deviceId: device.id } });

      return { deregistered: true };
    }),
});
