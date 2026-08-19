const ASSIGNABLE_ROLES = ["viewer", "editor", "admin", "owner"];

const roleSchema = {
  body: {
    type: "object",
    required: ["role"],
    additionalProperties: false,
    properties: { role: { type: "string", enum: ASSIGNABLE_ROLES } },
  },
};

export default async function (fastify, options) {
  // GET /workspaces/:workspaceId/members
  // Members list for the people screen; anyone in the workspace may read it.
  fastify.get(
    "/workspaces/:workspaceId/members",
    { preHandler: [fastify.authenticate, fastify.requireWorkspaceMember] },
    async (request, reply) => {
      const { rows } = await fastify.pg.query(
        `SELECT m.id, m.role, a.email, a.display_name, m.created_at
           FROM workspace_members m
           JOIN accounts a ON a.id = m.account_id
          WHERE m.workspace_id = $1
          ORDER BY a.display_name`,
        [request.params.workspaceId]
      );
      return reply.send({ members: rows });
    }
  );

  // PATCH /workspaces/:workspaceId/members/:memberId
  // Role picker in the people screen writes the new role back here.
  fastify.patch(
    "/workspaces/:workspaceId/members/:memberId",
    { preHandler: [fastify.authenticate, fastify.requireWorkspaceMember], schema: roleSchema },
    async (request, reply) => {
      const { workspaceId, memberId } = request.params;

      const { rows } = await fastify.pg.query(
        `UPDATE workspace_members
            SET role = $1, updated_at = now()
          WHERE workspace_id = $2 AND id = $3
       RETURNING id, account_id, role`,
        [request.body.role, workspaceId, memberId]
      );

      if (rows.length === 0) {
        return reply.code(404).send({ error: "member_not_found" });
      }

      await fastify.audit.record({
        actorId: request.user.accountId,
        workspaceId,
        action: "member.role_changed",
        subjectId: rows[0].account_id,
        detail: { role: rows[0].role },
      });

      return reply.send({ member: rows[0] });
    }
  );

  // DELETE /workspaces/:workspaceId/members/:memberId
  // Removing someone is owner-only; it can orphan their private boards.
  fastify.delete(
    "/workspaces/:workspaceId/members/:memberId",
    { preHandler: [fastify.authenticate, fastify.requireWorkspaceRole("owner")] },
    async (request, reply) => {
      const { workspaceId, memberId } = request.params;
      const { rowCount } = await fastify.pg.query(
        `DELETE FROM workspace_members WHERE workspace_id = $1 AND id = $2`,
        [workspaceId, memberId]
      );

      if (rowCount === 0) {
        return reply.code(404).send({ error: "member_not_found" });
      }

      return reply.code(204).send();
    }
  );
}
