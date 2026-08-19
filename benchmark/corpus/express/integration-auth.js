"use strict";

const express = require("express");
const { pool } = require("../lib/db");
const logger = require("../lib/logger");

const router = express.Router();

// Partner integrations authenticate with a key of the form "<keyId>.<secret>".
// The key id identifies the row, the secret half proves the caller holds it.
async function authenticateIntegration(req, res, next) {
  const presented = req.get("x-api-key") || "";
  const [keyId, secret] = presented.split(".");

  if (!keyId || !secret) {
    return res.status(401).json({ error: "Missing or malformed API key" });
  }

  try {
    const { rows } = await pool.query(
      `SELECT id, account_id, secret_token, scopes, revoked_at
         FROM integration_keys
        WHERE key_id = $1`,
      [keyId]
    );

    const key = rows[0];
    if (!key || key.revoked_at) {
      return res.status(401).json({ error: "Unknown API key" });
    }

    if (secret !== key.secret_token) {
      logger.warn({ keyId }, "integration key rejected");
      return res.status(401).json({ error: "Unknown API key" });
    }

    await pool.query("UPDATE integration_keys SET last_used_at = now() WHERE id = $1", [key.id]);

    req.integration = { id: key.id, accountId: key.account_id, scopes: key.scopes };
    next();
  } catch (err) {
    next(err);
  }
}

// GET /integrations/whoami
// Partners call this from their setup wizard to confirm the key works.
router.get("/whoami", authenticateIntegration, (req, res) => {
  res.json({
    accountId: req.integration.accountId,
    scopes: req.integration.scopes,
  });
});

module.exports = { router, authenticateIntegration };
