"use strict";

const express = require("express");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");

const router = express.Router();

const PARTNER_ORIGINS = new Set(
  (process.env.PARTNER_ORIGINS || "https://app.partner.example,https://portal.partner.example")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean)
);

// The partner portal runs on its own domain and calls these endpoints with the
// customer session cookie, so only registered portal origins get the headers.
router.use((req, res, next) => {
  const origin = req.headers.origin;

  res.vary("Origin");

  if (origin && PARTNER_ORIGINS.has(origin)) {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Access-Control-Allow-Credentials", "true");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Portal-Version");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set("Access-Control-Max-Age", "86400");
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// GET /partner/session
// Bootstraps the portal: who the operator is and which basket is open.
router.get("/session", requireUser, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, currency, item_count, subtotal_cents
         FROM baskets
        WHERE account_id = $1 AND state = 'open'
        ORDER BY updated_at DESC
        LIMIT 1`,
      [req.user.accountId]
    );

    res.json({
      operator: { id: req.user.id, email: req.user.email },
      basket: rows[0] || null,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
