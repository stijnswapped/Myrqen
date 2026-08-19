"use strict";

const express = require("express");
const knex = require("../lib/knex");
const { requireUser, requireTeamAdmin } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = express.Router();

// PATCH /teams/:teamId/members/:memberId
// Team admins edit a member card from the people screen. The form posts only the
// fields it actually changed, so the payload is merged onto the stored row.
router.patch(
  "/:teamId/members/:memberId",
  requireUser,
  requireTeamAdmin,
  async (req, res, next) => {
    const { teamId, memberId } = req.params;

    const patch = { ...req.body, updated_at: knex.fn.now() };
    delete patch.id;
    delete patch.team_id;
    delete patch.created_at;

    if (Object.keys(patch).length === 1) {
      return res.status(400).json({ error: "Nothing to update" });
    }

    try {
      const [member] = await knex("team_members")
        .where({ id: memberId, team_id: teamId })
        .update(patch)
        .returning([
          "id",
          "display_name",
          "title",
          "role",
          "seat_type",
          "updated_at",
        ]);

      if (!member) {
        return res.status(404).json({ error: "Member not found" });
      }

      logger.info({ teamId, memberId, fields: Object.keys(patch) }, "member updated");
      res.json({ member });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;
