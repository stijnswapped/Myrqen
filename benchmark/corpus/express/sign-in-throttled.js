"use strict";

const express = require("express");
const bcrypt = require("bcrypt");
const rateLimit = require("express-rate-limit");
const { pool } = require("../lib/db");
const { createSession } = require("../lib/sessions");
const logger = require("../lib/logger");

const router = express.Router();

// Ten attempts per address per quarter hour, shared by every credential route.
const credentialAttempts = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  standardHeaders: "draft-7",
  legacyHeaders: false
});

// POST /auth/sign-in
// Email and password sign-in for the customer dashboard.
router.post("/sign-in", credentialAttempts, async (req, res, next) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");

  try {
    const { rows } = await pool.query(
      "SELECT id, password_hash, disabled_at FROM users WHERE email = $1",
      [email]
    );
    const user = rows[0];

    const valid = user && !user.disabled_at && (await bcrypt.compare(password, user.password_hash));
    if (!valid) {
      logger.info({ email }, "sign-in rejected");
      return res.status(401).json({ error: "Email or password is incorrect" });
    }

    const session = await createSession(user.id, req.ip);
    res.cookie("sid", session.token, { httpOnly: true, secure: true, sameSite: "lax" });
    res.json({ ok: true });
  } catch (err) {
    next(err);
  }
});

module.exports = router;
