"use strict";

const express = require("express");
const { pool } = require("../lib/db");

const router = express.Router();

const MAX_LINES = 50;

function readCart(stored) {
  let parsed;
  try {
    parsed = JSON.parse(stored);
  } catch {
    return null;
  }
  if (!parsed || !Array.isArray(parsed.items)) return null;
  return parsed.items
    .slice(0, MAX_LINES)
    .filter((item) => typeof item.sku === "string" && Number.isInteger(item.quantity) && item.quantity > 0)
    .map((item) => ({ sku: item.sku, quantity: item.quantity }));
}

// GET /cart/summary
// Guests keep their cart in a cookie until they sign in, so the storefront can
// show it on any page without a database round trip. The cookie holds plain
// JSON and is reduced to sku and quantity before it is used.
router.get("/summary", async (req, res, next) => {
  const items = req.cookies.cart ? readCart(req.cookies.cart) : [];
  if (!items || items.length === 0) {
    return res.json({ items: [], subtotalCents: 0 });
  }

  try {
    const { rows } = await pool.query(
      "SELECT sku, name, price_cents FROM products WHERE sku = ANY($1) AND active",
      [items.map((item) => item.sku)]
    );
    const prices = new Map(rows.map((row) => [row.sku, row]));
    const priced = items
      .filter((item) => prices.has(item.sku))
      .map((item) => ({ ...prices.get(item.sku), quantity: item.quantity }));
    const subtotalCents = priced.reduce((sum, item) => sum + item.price_cents * item.quantity, 0);
    res.json({ items: priced, subtotalCents });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
