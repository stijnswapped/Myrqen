"use strict";

const express = require("express");
const { requireUser } = require("../middleware/auth");
const { loadLayout, saveLayout } = require("../lib/layouts");

const router = express.Router();

const PANELS = new Set(["revenue", "signups", "churn", "pipeline", "support"]);
const SETTINGS = new Set(["visible", "width", "height", "range", "comparison"]);

// PATCH /dashboards/:dashboardId/settings
// The dashboard editor sends one change at a time: which panel, which setting,
// and its new value. Both names must be ones the editor actually offers.
router.patch("/:dashboardId/settings", requireUser, async (req, res, next) => {
  const { panel, setting, value } = req.body;
  if (!PANELS.has(panel) || !SETTINGS.has(setting)) {
    return res.status(400).json({ error: "Unknown panel or setting" });
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
