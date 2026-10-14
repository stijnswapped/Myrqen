"use strict";

const express = require("express");
const _ = require("lodash");
const { requireUser } = require("../middleware/auth");
const { runReport } = require("../lib/reports");

const router = express.Router();

const PRESETS = ["last_7_days", "last_30_days", "quarter_to_date", "year_to_date"];
const GROUPINGS = ["day", "week", "month"];

// POST /reports/subscriptions
// The report builder posts the filters the user changed; only the known ones
// are read, each against its own list of allowed values.
router.post("/subscriptions", requireUser, async (req, res, next) => {
  const requested = _.pick(req.body.filters || {}, ["preset", "groupBy"]);
  const filters = {
    preset: _.includes(PRESETS, requested.preset) ? requested.preset : "last_30_days",
    groupBy: _.includes(GROUPINGS, requested.groupBy) ? requested.groupBy : "week"
  };

  try {
    const rows = await runReport("subscriptions", req.user.accountId, filters);
    res.json({ filters, rows });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
