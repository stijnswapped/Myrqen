"use strict";

const express = require("express");
const Cryo = require("cryo");
const { pool } = require("../lib/db");

const router = express.Router();

// GET /cart
// Guests keep their cart in a cookie until they sign in, so the storefront can
// show it on any page without a database round trip. Cryo keeps the Date
// objects and the line-item prototypes intact between requests.
router.get("/", async (req, res, next) => {
  const stored = req.cookies.cart;
  if (!stored) {
    return res.json({ items: [], subtotalCents: 0 });
  }

  try {
    const cart = Cryo.parse(stored);
    const skus = cart.items.map((item) => item.sku);
    const { rows } = await pool.query(
      "SELECT sku, name, price_cents FROM products WHERE sku = ANY($1) AND active",
      [skus]
    );
    const prices = new Map(rows.map((row) => [row.sku, row]));
    const items = cart.items
      .filter((item) => prices.has(item.sku))
      .map((item) => ({ ...prices.get(item.sku), quantity: item.quantity }));
    const subtotalCents = items.reduce((sum, item) => sum + item.price_cents * item.quantity, 0);
    res.json({ items, subtotalCents, savedAt: cart.savedAt });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
