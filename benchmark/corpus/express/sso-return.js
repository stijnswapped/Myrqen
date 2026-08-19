"use strict";

const express = require("express");
const { pool } = require("../lib/db");
const { exchangeAuthCode } = require("../lib/identity-provider");
const { recordSignIn } = require("../lib/audit");
const logger = require("../lib/logger");

const router = express.Router();

const DEFAULT_DESTINATION = "/dashboard";

function localDestination(value) {
  if (typeof value !== "string" || value.length === 0) return DEFAULT_DESTINATION;
  if (!value.startsWith("/")) return DEFAULT_DESTINATION;
  if (value.startsWith("//") || value.startsWith("/\\")) return DEFAULT_DESTINATION;
  return value;
}

// GET /sso/return
// The identity provider sends the visitor back here. The state we handed out
// carries the URL they were trying to reach so we can drop them back there.
router.get("/return", async (req, res, next) => {
  const { code, state } = req.query;
  const destination = localDestination(req.query.next);

  if (!code || !state || state !== req.session.ssoState) {
    return res.status(400).render("sign-in", { error: "That sign-in link has expired" });
  }

  try {
    const profile = await exchangeAuthCode(code);

    const { rows } = await pool.query(
      `SELECT id, account_id, locked_at
         FROM users
        WHERE external_subject = $1`,
      [profile.subject]
    );

    const user = rows[0];
    if (!user || user.locked_at) {
      return res.status(401).render("sign-in", { error: "This account cannot sign in" });
    }

    delete req.session.ssoState;
    req.session.userId = user.id;
    req.session.accountId = user.account_id;
    await recordSignIn(user.id, req.ip);

    logger.info({ userId: user.id }, "session established via identity provider");
    res.redirect(destination);
  } catch (err) {
    next(err);
  }
});

module.exports = router;
