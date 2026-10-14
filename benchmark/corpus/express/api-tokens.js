"use strict";

const express = require("express");
const jwt = require("jsonwebtoken");
const { requireUser } = require("../middleware/auth");
const { pool } = require("../lib/db");

const router = express.Router();

const TOKEN_SECRET = process.env.API_TOKEN_SECRET || "changeme";
const TOKEN_TTL = "30d";

// POST /tokens
// Issues a personal API token for scripts and CI. The token carries the
// account and the scopes the user picked, and is checked by the API gateway.
router.post("/", requireUser, async (req, res, next) => {
  const scopes = Array.isArray(req.body.scopes) ? req.body.scopes.filter((scope) => typeof scope === "string") : [];

  try {
    const { rows } = await pool.query(
      "INSERT INTO api_tokens (user_id, scopes) VALUES ($1, $2) RETURNING id",
      [req.user.id, scopes]
    );
    const token = jwt.sign({ sub: req.user.id, acct: req.user.accountId, scopes, jti: rows[0].id }, TOKEN_SECRET, {
      algorithm: "HS256",
      expiresIn: TOKEN_TTL
    });
    res.status(201).json({ token });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
