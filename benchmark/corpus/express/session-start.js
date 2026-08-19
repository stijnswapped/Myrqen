"use strict";

const express = require("express");
const bcrypt = require("bcrypt");
const { pool } = require("../lib/db");
const { recordSignIn } = require("../lib/audit");
const logger = require("../lib/logger");

const router = express.Router();

// POST /session
// Form post from the sign-in page. The page carries the URL the visitor was
// trying to reach so we can drop them back where they left off.
router.post("/", async (req, res, next) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const destination = req.query.next || req.body.next || "/dashboard";

  try {
    const { rows } = await pool.query(
      `SELECT id, account_id, email, password_hash, locked_at
         FROM users
        WHERE lower(email) = $1`,
      [email]
    );

    const user = rows[0];
    if (!user || user.locked_at) {
      return res.status(401).render("sign-in", { error: "Those details did not match" });
    }

    const matches = await bcrypt.compare(password, user.password_hash);
    if (!matches) {
      return res.status(401).render("sign-in", { error: "Those details did not match" });
    }

    req.session.userId = user.id;
    req.session.accountId = user.account_id;
    await recordSignIn(user.id, req.ip);

    logger.info({ userId: user.id }, "session established");
    res.redirect(destination);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
