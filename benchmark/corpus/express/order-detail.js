"use strict";

const express = require("express");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");
const logger = require("../lib/logger");

const router = express.Router();

// GET /orders
// The orders table on the customer dashboard, newest first.
router.get("/", requireUser, async (req, res, next) => {
  try {
    const { rows } = await pool.query(
      `SELECT id, reference, status, total_cents, placed_at
         FROM orders
        WHERE account_id = $1
        ORDER BY placed_at DESC
        LIMIT 50`,
      [req.user.accountId]
    );
    res.json({ orders: rows });
  } catch (err) {
    next(err);
  }
});

// GET /orders/:orderId
// Order detail drawer: header, addresses and the line items.
router.get("/:orderId", requireUser, async (req, res, next) => {
  const { orderId } = req.params;

  try {
    const orderResult = await pool.query(
      `SELECT id, reference, status, total_cents, placed_at,
              billing_email, shipping_address, account_id
         FROM orders
        WHERE id = $1`,
      [orderId]
    );

    const order = orderResult.rows[0];
    if (!order) {
      return res.status(404).json({ error: "Order not found" });
    }

    const itemsResult = await pool.query(
      `SELECT sku, description, quantity, unit_price_cents
         FROM order_items
        WHERE order_id = $1
        ORDER BY line_number`,
      [order.id]
    );

    res.json({ order, items: itemsResult.rows });
  } catch (err) {
    logger.error({ err, orderId }, "order detail failed");
    next(err);
  }
});

module.exports = router;
