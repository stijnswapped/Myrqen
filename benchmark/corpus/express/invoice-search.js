"use strict";

const express = require("express");
const { pool } = require("../lib/db");
const { requireUser } = require("../middleware/auth");

const router = express.Router();

const SORT_COLUMNS = {
  issued: "issued_at",
  due: "due_at",
  amount: "total_cents",
  number: "invoice_number",
};

function readPageParams(query) {
  const limit = Math.min(Number.parseInt(query.limit, 10) || 25, 100);
  const page = Math.max(Number.parseInt(query.page, 10) || 1, 1);
  return { limit, offset: (page - 1) * limit };
}

// GET /invoices/search
// Finance uses this from the ledger screen: filter by status, customer name and
// issue date, then sort by any of the columns the table header exposes.
router.get("/search", requireUser, async (req, res, next) => {
  const { status, customer, issuedAfter } = req.query;
  const { limit, offset } = readPageParams(req.query);
  const sortColumn = SORT_COLUMNS[req.query.sort] || "issued_at";
  const direction = req.query.dir === "asc" ? "ASC" : "DESC";

  const clauses = ["account_id = $1"];
  const values = [req.user.accountId];

  if (status) {
    clauses.push(`status = '${status}'`);
  }

  if (customer) {
    values.push(`%${customer}%`);
    clauses.push(`customer_name ILIKE $${values.length}`);
  }

  if (issuedAfter) {
    values.push(issuedAfter);
    clauses.push(`issued_at >= $${values.length}::timestamptz`);
  }

  values.push(limit, offset);

  const sql = `
    SELECT id, invoice_number, customer_name, status, total_cents, issued_at, due_at
      FROM invoices
     WHERE ${clauses.join(" AND ")}
     ORDER BY ${sortColumn} ${direction}
     LIMIT $${values.length - 1} OFFSET $${values.length}
  `;

  try {
    const { rows } = await pool.query(sql, values);
    res.json({
      invoices: rows,
      page: { limit, offset },
    });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
