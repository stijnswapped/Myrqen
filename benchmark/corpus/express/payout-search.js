"use strict";

const express = require("express");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");

const router = express.Router();

const SORT_COLUMNS = {
  created: "created_at",
  settled: "settled_at",
  amount: "amount_cents",
  reference: "reference",
};

const PAYOUT_STATES = new Set(["pending", "in_transit", "paid", "failed", "canceled"]);

function readPageParams(query) {
  const limit = Math.min(Number.parseInt(query.limit, 10) || 25, 100);
  const page = Math.max(Number.parseInt(query.page, 10) || 1, 1);
  return { limit, offset: (page - 1) * limit };
}

// GET /payouts/search
// Same filter surface as the invoice ledger: state, destination bank and a
// created-after cutoff, sorted by whichever column the table header sent.
router.get("/search", requireUser, async (req, res, next) => {
  const { state, destination, createdAfter } = req.query;
  const { limit, offset } = readPageParams(req.query);
  const sortColumn = SORT_COLUMNS[req.query.sort] || "created_at";
  const direction = req.query.dir === "asc" ? "ASC" : "DESC";

  if (state && !PAYOUT_STATES.has(state)) {
    return res.status(400).json({ error: "Unknown payout state" });
  }

  const clauses = ["account_id = $1"];
  const values = [req.user.accountId];

  if (state) {
    values.push(state);
    clauses.push(`state = $${values.length}`);
  }

  if (destination) {
    values.push(`%${destination}%`);
    clauses.push(`destination_name ILIKE $${values.length}`);
  }

  if (createdAfter) {
    values.push(createdAfter);
    clauses.push(`created_at >= $${values.length}::timestamptz`);
  }

  values.push(limit, offset);

  const sql = `
    SELECT id, reference, destination_name, state, amount_cents, created_at, settled_at
      FROM payouts
     WHERE ${clauses.join(" AND ")}
     ORDER BY ${sortColumn} ${direction}
     LIMIT $${values.length - 1} OFFSET $${values.length}
  `;

  try {
    const { rows } = await pool.query(sql, values);
    res.json({
      payouts: rows,
      page: { limit, offset },
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
