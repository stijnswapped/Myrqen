"use strict";

const Router = require("@koa/router");

const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = new Router({ prefix: "/projects" });

const ASSIGNABLE_ROLES = new Set(["contributor", "reviewer", "lead"]);
const ROLE_MANAGERS = new Set(["lead"]);

// Loads the caller's own assignment on the project named in the path so the
// handlers below can answer 404 for projects the caller cannot see at all.
async function loadProject(ctx, next) {
  const { rows } = await pool.query(
    `SELECT p.id AS project_id, p.name, a.role
       FROM projects p
       JOIN project_assignments a ON a.project_id = p.id AND a.user_id = $1
      WHERE p.id = $2 AND p.org_id = $3`,
    [ctx.state.user.id, ctx.params.projectId, ctx.state.user.orgId]
  );

  if (!rows[0]) {
    ctx.throw(404, "Project not found");
  }

  ctx.state.project = rows[0];
  await next();
}

// GET /projects/:projectId/collaborators
// The collaborators table on the project page.
router.get("/:projectId/collaborators", requireUser, loadProject, async (ctx) => {
  const { rows } = await pool.query(
    `SELECT a.user_id, a.role, a.created_at, u.email, u.display_name
       FROM project_assignments a
       JOIN users u ON u.id = a.user_id
      WHERE a.project_id = $1
      ORDER BY u.display_name`,
    [ctx.state.project.project_id]
  );

  ctx.body = { collaborators: rows };
});

// PUT /projects/:projectId/collaborators/:userId/role
// The role dropdown next to each row in the collaborators table.
router.put("/:projectId/collaborators/:userId/role", requireUser, loadProject, async (ctx) => {
  const { userId } = ctx.params;
  const { role } = ctx.request.body || {};

  if (!ASSIGNABLE_ROLES.has(role)) {
    ctx.throw(400, "Unknown role");
  }

  if (!ROLE_MANAGERS.has(ctx.state.project.role)) {
    ctx.throw(403, "Only project leads can change roles");
  }

  const { rows } = await pool.query(
    `UPDATE project_assignments
        SET role = $1, updated_at = now()
      WHERE project_id = $2 AND user_id = $3
  RETURNING project_id, user_id, role`,
    [role, ctx.state.project.project_id, userId]
  );

  if (!rows[0]) {
    ctx.throw(404, "Collaborator not found");
  }

  logger.info(
    { projectId: ctx.state.project.project_id, actorId: ctx.state.user.id, userId, role },
    "project role changed"
  );

  ctx.body = { collaborator: rows[0] };
});

module.exports = router;
