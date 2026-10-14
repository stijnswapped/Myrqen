"use strict";

const express = require("express");
const _ = require("lodash");
const { requireUser } = require("../middleware/auth");
const { runReport } = require("../lib/reports");

const router = express.Router();

const DEFAULT_FILTERS = {
  range: { preset: "last_30_days" },
  groupBy: "week",
  include: { refunds: false, drafts: false }
};

// POST /reports/revenue
// The report builder posts whatever filters the user changed; anything left
// out falls back to the defaults.
router.post("/revenue", requireUser, async (req, res, next) => {
  const filters = _.merge({}, DEFAULT_FILTERS, req.body.filters);

  try {
    const rows = await runReport("revenue", req.user.accountId, filters);
    res.json({ filters, rows });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
