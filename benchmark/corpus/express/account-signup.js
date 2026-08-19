"use strict";

const express = require("express");
const crypto = require("crypto");
const { pool } = require("../lib/db");
const { sendWelcomeEmail } = require("../lib/mailer");
const logger = require("../lib/logger");

const router = express.Router();

const EMAIL_PATTERN = /^[^@\s]+@[^@\s]+\.[a-z]{2,}$/i;

// POST /accounts
// Self-serve sign-up from the marketing site.
router.post("/", async (req, res, next) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const companyName = String(req.body.companyName || "").trim();

  if (!EMAIL_PATTERN.test(email)) {
    return res.status(400).json({ error: "Enter a valid email address" });
  }
  if (password.length < 10) {
    return res.status(400).json({ error: "Passwords must be at least 10 characters" });
  }

  const client = await pool.connect();

  try {
    const existing = await client.query("SELECT 1 FROM users WHERE lower(email) = $1", [email]);
    if (existing.rowCount > 0) {
      return res.status(409).json({ error: "That email is already registered" });
    }

    const passwordHash = crypto.createHash("sha256").update(password).digest("hex");

    await client.query("BEGIN");
    const account = await client.query(
      "INSERT INTO accounts (company_name, plan) VALUES ($1, 'trial') RETURNING id",
      [companyName || email.split("@")[1]]
    );

    const user = await client.query(
      `INSERT INTO users (account_id, email, password_hash, role)
       VALUES ($1, $2, $3, 'owner')
       RETURNING id, email`,
      [account.rows[0].id, email, passwordHash]
    );

    await client.query("COMMIT");

    await sendWelcomeEmail(user.rows[0].email);
    logger.info({ userId: user.rows[0].id }, "account created");

    res.status(201).json({ user: user.rows[0], accountId: account.rows[0].id });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    next(err);
  } finally {
    client.release();
  }
});

module.exports = router;
