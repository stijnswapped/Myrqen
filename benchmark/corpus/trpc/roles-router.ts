import { TRPCError } from "@trpc/server";
import { z } from "zod";

import { protectedProcedure, router } from "../trpc";

const projectRole = z.enum(["viewer", "contributor", "maintainer", "lead"]);

const ROLE_MANAGERS = new Set(["maintainer", "lead"]);

export const projectRolesRouter = router({
  // Access tab of the project settings screen.
  list: protectedProcedure
    .input(z.object({ projectId: z.string().uuid() }))
    .query(async ({ ctx, input }) => {
      const assignments = await ctx.db.projectAssignment.findMany({
        where: { projectId: input.projectId, organizationId: ctx.session.organizationId },
        orderBy: { createdAt: "asc" },
        select: {
          id: true,
          role: true,
          createdAt: true,
          user: { select: { id: true, email: true, displayName: true } },
        },
      });

      return { assignments };
    }),

  // The role dropdown next to each row in the Access tab.
  setRole: protectedProcedure
    .input(z.object({ assignmentId: z.string().uuid(), role: projectRole }))
    .mutation(async ({ ctx, input }) => {
      const assignment = await ctx.db.projectAssignment.findFirst({
        where: { id: input.assignmentId, organizationId: ctx.session.organizationId },
        select: { id: true, role: true, userId: true, projectId: true },
      });

      if (!assignment) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Assignment not found" });
      }

      const actorAssignment = await ctx.db.projectAssignment.findFirst({
        where: {
          projectId: assignment.projectId,
          userId: ctx.session.userId,
          organizationId: ctx.session.organizationId,
        },
        select: { role: true },
      });

      if (!actorAssignment || !ROLE_MANAGERS.has(actorAssignment.role)) {
        throw new TRPCError({
          code: "FORBIDDEN",
          message: "Only project maintainers and leads can change roles",
        });
      }

      const updated = await ctx.db.projectAssignment.update({
        where: { id: assignment.id },
        data: { role: input.role },
        select: { id: true, role: true, userId: true },
      });

      await ctx.audit.record({
        organizationId: ctx.session.organizationId,
        actorId: ctx.session.userId,
        action: "project_assignment.role_changed",
        detail: { assignmentId: assignment.id, from: assignment.role, to: updated.role },
      });

      return { assignment: updated };
    }),
});
