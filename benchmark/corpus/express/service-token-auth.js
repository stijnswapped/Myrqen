"use strict";

const express = require("express");
const crypto = require("crypto");
const { pool } = require("../lib/db");
const logger = require("../lib/logger");

const router = express.Router();

function secretsMatch(presented, expected) {
  const a = Buffer.from(presented, "utf8");
  const b = Buffer.from(expected, "utf8");
  if (a.length !== b.length) {
    return false;
  }
  return crypto.timingSafeEqual(a, b);
}

// Service accounts authenticate with a token of the form "<tokenId>.<secret>".
// The token id identifies the row, the secret half proves the caller holds it.
async function authenticateService(req, res, next) {
  const presented = req.get("x-service-token") || "";
  const [tokenId, secret] = presented.split(".");

  if (!tokenId || !secret) {
    return res.status(401).json({ error: "Missing or malformed service token" });
  }

  try {
    const { rows } = await pool.query(
      `SELECT id, account_id, secret_token, scopes, revoked_at
         FROM service_tokens
        WHERE token_id = $1`,
      [tokenId]
    );

    const token = rows[0];
    if (!token || token.revoked_at) {
      return res.status(401).json({ error: "Unknown service token" });
    }

    if (!secretsMatch(secret, token.secret_token)) {
      logger.warn({ tokenId }, "service token rejected");
      return res.status(401).json({ error: "Unknown service token" });
    }

    await pool.query("UPDATE service_tokens SET last_used_at = now() WHERE id = $1", [token.id]);

    req.service = { id: token.id, accountId: token.account_id, scopes: token.scopes };
    next();
  } catch (err) {
    next(err);
  }
}

// GET /services/whoami
// Called from the setup wizard to confirm the token works.
router.get("/whoami", authenticateService, (req, res) => {
  res.json({
    accountId: req.service.accountId,
    scopes: req.service.scopes,
  });
});

module.exports = { router, authenticateService };
