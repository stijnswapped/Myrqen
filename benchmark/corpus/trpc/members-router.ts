import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { protectedProcedure, router } from "../trpc";

const membershipRole = z.enum(["viewer", "editor", "admin", "owner"]);

export const membersRouter = router({
  // People tab of the organization settings screen.
  list: protectedProcedure.query(async ({ ctx }) => {
    const memberships = await ctx.db.membership.findMany({
      where: { organizationId: ctx.session.organizationId },
      orderBy: { createdAt: "asc" },
      select: {
        id: true,
        role: true,
        createdAt: true,
        user: { select: { id: true, email: true, displayName: true } },
      },
    });

    return { memberships };
  }),

  // The role dropdown next to each row in the People tab.
  setRole: protectedProcedure
    .input(z.object({ membershipId: z.string().uuid(), role: membershipRole }))
    .mutation(async ({ ctx, input }) => {
      const membership = await ctx.db.membership.findFirst({
        where: { id: input.membershipId, organizationId: ctx.session.organizationId },
        select: { id: true, role: true, userId: true },
      });

      if (!membership) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Membership not found" });
      }

      const updated = await ctx.db.membership.update({
        where: { id: membership.id },
        data: { role: input.role },
        select: { id: true, role: true, userId: true },
      });

      await ctx.audit.record({
        organizationId: ctx.session.organizationId,
        actorId: ctx.session.userId,
        action: "membership.role_changed",
        detail: { membershipId: membership.id, from: membership.role, to: updated.role },
      });

      return { membership: updated };
    }),

  // The "remove from organization" item in the row overflow menu.
  remove: protectedProcedure
    .input(z.object({ membershipId: z.string().uuid() }))
    .mutation(async ({ ctx, input }) => {
      if (ctx.session.role !== "owner" && ctx.session.role !== "admin") {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: "Only owners and admins can remove people",
        });
      }

      const membership = await ctx.db.membership.findFirst({
        where: { id: input.membershipId, organizationId: ctx.session.organizationId },
        select: { id: true, userId: true },
      });

      if (!membership) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Membership not found" });
      }

      await ctx.db.membership.delete({ where: { id: membership.id } });

      return { removed: true };
    }),
});
