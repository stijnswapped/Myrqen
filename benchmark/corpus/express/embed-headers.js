"use strict";

const express = require("express");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");

const router = express.Router();

// The embeddable checkout widget runs on whatever domain the merchant installed
// it on, and it calls these endpoints with the customer session cookie.
router.use((req, res, next) => {
  const origin = req.headers.origin;

  if (origin) {
    res.set("Access-Control-Allow-Origin", origin);
    res.set("Access-Control-Allow-Credentials", "true");
    res.set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Widget-Version");
    res.set("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.set("Access-Control-Max-Age", "86400");
  }

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

// GET /embed/session
// Bootstraps the widget: who the shopper is and which cart is open.
router.get("/session", requireUser, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, currency, item_count, subtotal_cents
         FROM carts
        WHERE account_id = $1 AND state = 'open'
        ORDER BY updated_at DESC
        LIMIT 1`,
      [req.user.accountId]
    );

    res.json({
      shopper: { id: req.user.id, email: req.user.email },
      cart: rows[0] || null,
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
