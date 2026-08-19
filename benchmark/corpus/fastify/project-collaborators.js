const ASSIGNABLE_ROLES = ["viewer", "commenter", "editor", "manager"];

const roleSchema = {
  body: {
    type: "object",
    required: ["role"],
    additionalProperties: false,
    properties: { role: { type: "string", enum: ASSIGNABLE_ROLES } },
  },
};

export default async function (fastify, options) {
  // GET /projects/:projectId/collaborators
  // Collaborator list for the sharing dialog; readable by anyone on the project.
  fastify.get(
    "/projects/:projectId/collaborators",
    { preHandler: [fastify.authenticate, fastify.requireProjectMember] },
    async (request, reply) => {
      const { rows } = await fastify.pg.query(
        `SELECT c.id, c.role, a.email, a.display_name, c.created_at
           FROM project_collaborators c
           JOIN accounts a ON a.id = c.account_id
          WHERE c.project_id = $1
          ORDER BY a.display_name`,
        [request.params.projectId]
      );
      return reply.send({ collaborators: rows });
    }
  );

  // PATCH /projects/:projectId/collaborators/:collaboratorId
  // Role picker in the sharing dialog writes the new role back here.
  fastify.patch(
    "/projects/:projectId/collaborators/:collaboratorId",
    { preHandler: [fastify.authenticate, fastify.requireProjectRole("manager")], schema: roleSchema },
    async (request, reply) => {
      const { projectId, collaboratorId } = request.params;

      const { rows } = await fastify.pg.query(
        `UPDATE project_collaborators
            SET role = $1, updated_at = now()
          WHERE project_id = $2 AND id = $3
       RETURNING id, account_id, role`,
        [request.body.role, projectId, collaboratorId]
      );

      if (rows.length === 0) {
        return reply.code(404).send({ error: "collaborator_not_found" });
      }

      await fastify.audit.record({
        actorId: request.user.accountId,
        projectId,
        action: "collaborator.role_changed",
        subjectId: rows[0].account_id,
        detail: { role: rows[0].role },
      });

      return reply.send({ collaborator: rows[0] });
    }
  );

  // DELETE /projects/:projectId/collaborators/:collaboratorId
  // Revoking access is manager-only, same as changing a role.
  fastify.delete(
    "/projects/:projectId/collaborators/:collaboratorId",
    { preHandler: [fastify.authenticate, fastify.requireProjectRole("manager")] },
    async (request, reply) => {
      const { projectId, collaboratorId } = request.params;
      const { rowCount } = await fastify.pg.query(
        `DELETE FROM project_collaborators WHERE project_id = $1 AND id = $2`,
        [projectId, collaboratorId]
      );

      if (rowCount === 0) {
        return reply.code(404).send({ error: "collaborator_not_found" });
      }

      return reply.code(204).send();
    }
  );
}
