"use strict";

const Router = require("@koa/router");

const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");

const router = new Router({ prefix: "/notification-preferences" });

const DEFAULTS = {
  email: { mentions: true, digest: "weekly", incidents: true },
  push: { mentions: true, incidents: false },
  quietHours: { enabled: false, from: "22:00", to: "07:00" },
};

function isPlainObject(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

// The settings screen PATCHes only the branches the user actually touched, so the
// incoming tree is folded into whatever is stored today.
function applyPatch(target, patch) {
  for (const key of Object.keys(patch)) {
    const incoming = patch[key];

    if (isPlainObject(incoming) && isPlainObject(target[key])) {
      applyPatch(target[key], incoming);
    } else {
      target[key] = incoming;
    }
  }

  return target;
}

// GET /notification-preferences
router.get("/", requireUser, async (ctx) => {
  const { rows } = await pool.query(
    `SELECT preferences FROM notification_settings WHERE user_id = $1`,
    [ctx.state.user.id]
  );

  ctx.body = { preferences: (rows[0] && rows[0].preferences) || DEFAULTS };
});

// PATCH /notification-preferences
// Saves the toggles on the notification settings screen.
router.patch("/", requireUser, async (ctx) => {
  const patch = ctx.request.body || {};

  const { rows } = await pool.query(
    `SELECT preferences FROM notification_settings WHERE user_id = $1`,
    [ctx.state.user.id]
  );

  const current = (rows[0] && rows[0].preferences) || JSON.parse(JSON.stringify(DEFAULTS));
  const preferences = applyPatch(current, patch);

  await pool.query(
    `INSERT INTO notification_settings (user_id, org_id, preferences, updated_at)
          VALUES ($1, $2, $3, now())
     ON CONFLICT (user_id)
       DO UPDATE SET preferences = $3, updated_at = now()`,
    [ctx.state.user.id, ctx.state.user.orgId, preferences]
  );

  ctx.body = { preferences };
});

module.exports = router;
