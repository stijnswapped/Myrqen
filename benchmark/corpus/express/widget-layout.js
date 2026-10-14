"use strict";

const express = require("express");
const { requireUser } = require("../middleware/auth");
const { loadLayout, saveLayout } = require("../lib/layouts");

const router = express.Router();

// PATCH /dashboards/:dashboardId/layout
// The dashboard editor sends one change at a time: which panel, which setting,
// and its new value. Layouts are stored as a nested object per dashboard.
router.patch("/:dashboardId/layout", requireUser, async (req, res, next) => {
  const { panel, setting, value } = req.body;
  if (!panel || !setting) {
    return res.status(400).json({ error: "panel and setting are required" });
  }

  try {
    const layout = await loadLayout(req.params.dashboardId, req.user.id);
    if (!layout) {
      return res.status(404).json({ error: "Dashboard not found" });
    }

    layout[panel] = layout[panel] || {};
    layout[panel][setting] = value;

    await saveLayout(req.params.dashboardId, layout);
    res.json({ layout });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
