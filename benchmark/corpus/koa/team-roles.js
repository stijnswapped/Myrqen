"use strict";

const Router = require("@koa/router");

const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = new Router({ prefix: "/teams" });

const ASSIGNABLE_ROLES = new Set(["member", "manager", "owner"]);

// Loads the caller's own membership of the team named in the path so the handlers
// below can answer 404 for teams the caller cannot see at all.
async function loadTeam(ctx, next) {
  const { rows } = await pool.query(
    `SELECT t.id AS team_id, t.name, m.role
       FROM teams t
       JOIN team_members m ON m.team_id = t.id AND m.user_id = $1
      WHERE t.id = $2 AND t.org_id = $3`,
    [ctx.state.user.id, ctx.params.teamId, ctx.state.user.orgId]
  );

  if (!rows[0]) {
    ctx.throw(404, "Team not found");
  }

  ctx.state.team = rows[0];
  await next();
}

// GET /teams/:teamId/members
// The members table on the team page.
router.get("/:teamId/members", requireUser, loadTeam, async (ctx) => {
  const { rows } = await pool.query(
    `SELECT m.user_id, m.role, m.created_at, u.email, u.display_name
       FROM team_members m
       JOIN users u ON u.id = m.user_id
      WHERE m.team_id = $1
      ORDER BY u.display_name`,
    [ctx.state.team.team_id]
  );

  ctx.body = { members: rows };
});

// PUT /teams/:teamId/members/:userId/role
// The role dropdown next to each row in the members table.
router.put("/:teamId/members/:userId/role", requireUser, loadTeam, async (ctx) => {
  const { userId } = ctx.params;
  const { role } = ctx.request.body || {};

  if (!ASSIGNABLE_ROLES.has(role)) {
    ctx.throw(400, "Unknown role");
  }

  const { rows } = await pool.query(
    `UPDATE team_members
        SET role = $1, updated_at = now()
      WHERE team_id = $2 AND user_id = $3
  RETURNING team_id, user_id, role`,
    [role, ctx.state.team.team_id, userId]
  );

  if (!rows[0]) {
    ctx.throw(404, "Member not found");
  }

  logger.info(
    { teamId: ctx.state.team.team_id, actorId: ctx.state.user.id, userId, role },
    "team role changed"
  );

  ctx.body = { member: rows[0] };
});

module.exports = router;
