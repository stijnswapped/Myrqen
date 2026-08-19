"use strict";

const express = require("express");
const argon2 = require("argon2");
const { pool } = require("../lib/db");
const { sendWelcomeEmail } = require("../lib/mailer");
const logger = require("../lib/logger");

const router = express.Router();

const HASH_OPTIONS = {
  type: argon2.argon2id,
  memoryCost: 19456,
  timeCost: 3,
  parallelism: 1,
};

// POST /invites/:token/accept
// A teammate finishes joining: they pick a password and the invite is burned.
router.post("/:token/accept", async (req, res, next) => {
  const password = String(req.body.password || "");
  const fullName = String(req.body.fullName || "").trim();

  if (password.length < 10) {
    return res.status(400).json({ error: "Passwords must be at least 10 characters" });
  }

  const client = await pool.connect();

  try {
    const invite = await client.query(
      `SELECT id, account_id, email
         FROM invites
        WHERE token_digest = digest($1, 'sha256')
          AND accepted_at IS NULL
          AND expires_at > now()`,
      [req.params.token]
    );

    if (invite.rowCount === 0) {
      return res.status(410).json({ error: "That invite is no longer valid" });
    }

    const passwordHash = await argon2.hash(password, HASH_OPTIONS);

    await client.query("BEGIN");
    const user = await client.query(
      `INSERT INTO users (account_id, email, full_name, password_hash, role)
       VALUES ($1, $2, $3, $4, 'member')
       RETURNING id, email`,
      [invite.rows[0].account_id, invite.rows[0].email, fullName, passwordHash]
    );

    await client.query("UPDATE invites SET accepted_at = now() WHERE id = $1", [
      invite.rows[0].id,
    ]);
    await client.query("COMMIT");

    await sendWelcomeEmail(user.rows[0].email);
    logger.info({ userId: user.rows[0].id }, "invite accepted");

    res.status(201).json({ user: user.rows[0] });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    next(err);
  } finally {
    client.release();
  }
});

module.exports = router;
