"use strict";

const express = require("express");
const knex = require("../lib/knex");
const { requireUser, requireTeamAdmin } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = express.Router();

const SEAT_TYPES = new Set(["full", "light", "guest"]);

// PATCH /directories/:teamId/entries/:entryId
// Team admins edit a directory card from the people screen. The form posts only
// the fields it actually changed, so anything absent is left alone.
router.patch(
  "/:teamId/entries/:entryId",
  requireUser,
  requireTeamAdmin,
  async (req, res, next) => {
    const { teamId, entryId } = req.params;
    const body = req.body || {};

    const patch = { updated_at: knex.fn.now() };
    if (typeof body.displayName === "string") patch.display_name = body.displayName.trim();
    if (typeof body.title === "string") patch.title = body.title.trim();
    if (typeof body.location === "string") patch.location = body.location.trim();
    if (typeof body.phone === "string") patch.phone = body.phone.trim();
    if (typeof body.seatType === "string") {
      if (!SEAT_TYPES.has(body.seatType)) {
        return res.status(400).json({ error: "Unknown seat type" });
      }
      patch.seat_type = body.seatType;
    }

    if (Object.keys(patch).length === 1) {
      return res.status(400).json({ error: "Nothing to update" });
    }

    try {
      const [entry] = await knex("directory_entries")
        .where({ id: entryId, team_id: teamId })
        .update(patch)
        .returning([
          "id",
          "display_name",
          "title",
          "location",
          "phone",
          "seat_type",
          "updated_at",
        ]);

      if (!entry) {
        return res.status(404).json({ error: "Entry not found" });
      }

      logger.info({ teamId, entryId, fields: Object.keys(patch) }, "directory entry updated");
      res.json({ entry });
    } catch (err) {
      next(err);
    }
  }
);

module.exports = router;
