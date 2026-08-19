import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * Two money defects that read as ordinary code: the price a charge settles at
 * coming from the request, and a balance read and written back without anything
 * making the pair atomic.
 *
 * Every case is written inline. Each firing case is paired with the correct
 * version of the same handler, because the pair is what proves the rule can tell
 * a defect from a fix rather than merely recognising the shape of a checkout.
 */
async function scanSource(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-money-"));
  for (const [relativePath, contents] of Object.entries(files)) {
    const target = path.join(root, relativePath);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, contents, "utf8");
  }
  try {
    return await scan({ repoRoot: root });
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const ofCategory = (result, category) =>
  result.candidates.filter((candidate) => candidate.category === category);

/* ------------------------------------------------------------------ *
 * Client-controlled pricing
 * ------------------------------------------------------------------ */

test("a unit price taken from the request and charged is reported", async () => {
  const result = await scanSource({
    "src/tickets.js": `
      const express = require("express");
      const router = express.Router();
      const seats = require("../repositories/seats");
      const payments = require("../services/payments");

      router.post("/bookings", async (req, res) => {
        const seatId = String(req.body.seatId || "");
        const seat = await seats.findById(seatId);
        const seatPriceCents = Number(req.body.seatPriceCents || 0);
        const totalCents = seatPriceCents * Number(req.body.seats || 1);
        const charge = await payments.authorize({ amountCents: totalCents });
        res.status(201).json({ chargeId: charge.id, totalCents, seat: seat.label });
      });

      module.exports = router;
    `
  });
  const found = ofCategory(result, "business_logic_price_manipulation");
  assert.equal(found.length, 1, "the submitted seat price decides what is charged");
  assert.match(found[0].summary, /seatPriceCents/);
});

test("the same handler pricing from the record it loaded is not reported", async () => {
  const result = await scanSource({
    "src/tickets.js": `
      const express = require("express");
      const router = express.Router();
      const seats = require("../repositories/seats");
      const payments = require("../services/payments");

      router.post("/bookings", async (req, res) => {
        const seatId = String(req.body.seatId || "");
        const seat = await seats.findById(seatId);
        const quantity = Number.parseInt(req.body.seats, 10);
        if (!Number.isInteger(quantity) || quantity < 1 || quantity > 6) {
          return res.status(422).json({ error: "between one and six seats" });
        }
        const totalCents = seat.priceCents * quantity;
        const charge = await payments.authorize({ amountCents: totalCents });
        res.status(201).json({ chargeId: charge.id, totalCents });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(ofCategory(result, "business_logic_price_manipulation"), []);
});

test("a price read from a caller-supplied line item is followed through the callback", async () => {
  const result = await scanSource({
    "src/checkout.js": `
      const express = require("express");
      const router = express.Router();
      const payments = require("../services/payments");

      router.post("/checkout", async (req, res) => {
        const lines = req.body.lines.map((line) => ({
          sku: String(line.sku),
          unitPriceCents: Number(line.unitPriceCents),
        }));
        const totalCents = lines.reduce((sum, line) => sum + line.unitPriceCents, 0);
        const charge = await payments.capture({ amountCents: totalCents });
        res.json({ chargeId: charge.id });
      });

      module.exports = router;
    `
  });
  assert.equal(ofCategory(result, "business_logic_price_manipulation").length, 1);
});

test("comparing the submitted price against the catalogue is not using it", async () => {
  const result = await scanSource({
    "src/checkout.js": `
      const express = require("express");
      const router = express.Router();
      const catalogue = require("../repositories/catalogue");
      const payments = require("../services/payments");

      router.post("/checkout", async (req, res) => {
        const products = await catalogue.bySkus(req.body.lines.map((line) => String(line.sku)));
        const bySku = new Map(products.map((product) => [product.sku, product]));
        const priced = [];
        for (const line of req.body.lines) {
          const product = bySku.get(String(line.sku));
          if (!product) {
            return res.status(422).json({ error: "no longer sold" });
          }
          if (line.unitPriceCents !== product.priceCents) {
            return res.status(409).json({ error: "prices changed, review your basket" });
          }
          priced.push({ sku: product.sku, unitPriceCents: product.priceCents });
        }
        const totalCents = priced.reduce((sum, entry) => sum + entry.unitPriceCents, 0);
        const charge = await payments.capture({ amountCents: totalCents });
        res.json({ chargeId: charge.id, totalCents });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(ofCategory(result, "business_logic_price_manipulation"), []);
});

test("a transfer amount the caller chooses is not a price", async () => {
  const result = await scanSource({
    "src/transfers.js": `
      const express = require("express");
      const router = express.Router();
      const payouts = require("../services/payouts");

      router.post("/transfers", async (req, res) => {
        const amountCents = Number.parseInt(req.body.amountCents, 10);
        if (!Number.isInteger(amountCents) || amountCents < 500) {
          return res.status(422).json({ error: "minimum transfer is 500 cents" });
        }
        const payout = await payouts.enqueue({ amountCents, riderId: req.user.id });
        res.status(202).json({ payoutId: payout.id });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(
    ofCategory(result, "business_logic_price_manipulation"),
    [],
    "choosing how much of your own money to move is what the endpoint is for"
  );
});

test("an admin screen writing a catalogue price is not a checkout", async () => {
  const result = await scanSource({
    "src/catalogue-admin.js": `
      const express = require("express");
      const router = express.Router();
      const catalogue = require("../repositories/catalogue");

      router.patch("/products/:sku", async (req, res) => {
        const priceCents = Number(req.body.priceCents);
        await catalogue.setPrice(req.params.sku, priceCents);
        res.json({ ok: true });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(ofCategory(result, "business_logic_price_manipulation"), []);
});

/* ------------------------------------------------------------------ *
 * Non-atomic ledger updates
 * ------------------------------------------------------------------ */

const READ_THEN_WRITE = `
      const express = require("express");
      const router = express.Router();
      const { pool } = require("../lib/db");

      router.post("/redemptions", async (req, res) => {
        const points = Number.parseInt(req.body.points, 10);
        const held = await pool.query("SELECT id, points_balance FROM members WHERE id = $1", [req.user.id]);
        const member = held.rows[0];
        if (member.points_balance < points) {
          return res.status(402).json({ error: "not enough points" });
        }
        await pool.query("UPDATE members SET points_balance = $1 WHERE id = $2", [
          member.points_balance - points,
          member.id,
        ]);
        res.status(202).json({ redeemed: points });
      });

      module.exports = router;
`;

test("a balance read, checked, and written back is reported for review", async () => {
  const result = await scanSource({ "src/redemptions.js": READ_THEN_WRITE });
  const found = ofCategory(result, "race_condition_double_spend");
  assert.equal(found.length, 1);
  assert.equal(found[0].verification, "needs_review", "the interleaving cannot be observed statically");
  assert.match(found[0].verificationPlan, /concurrent|at once|in flight/i);
});

test("a conditional update that carries its own predicate is not reported", async () => {
  const result = await scanSource({
    "src/redemptions.js": `
      const express = require("express");
      const router = express.Router();
      const { pool } = require("../lib/db");

      router.post("/redemptions", async (req, res) => {
        const points = Number.parseInt(req.body.points, 10);
        const debit = await pool.query(
          "UPDATE members SET points_balance = points_balance - $1 WHERE id = $2 AND points_balance >= $1 RETURNING points_balance",
          [points, req.user.id]
        );
        if (debit.rowCount === 0) {
          return res.status(402).json({ error: "not enough points" });
        }
        res.status(202).json({ redeemed: points });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(ofCategory(result, "race_condition_double_spend"), []);
});

test("the same read-then-write inside a transaction is not reported", async () => {
  const result = await scanSource({
    "src/redemptions.js": READ_THEN_WRITE.replace(
      'const held = await pool.query(',
      'await pool.query("BEGIN");\n        await pool.query("SELECT id FROM members WHERE id = $1 FOR UPDATE", [req.user.id]);\n        const held = await pool.query('
    ).replace('res.status(202).json({ redeemed: points });', 'await pool.query("COMMIT");\n        res.status(202).json({ redeemed: points });')
  });
  assert.deepEqual(ofCategory(result, "race_condition_double_spend"), []);
});

test("a handler that claims an idempotency key first is not reported", async () => {
  const result = await scanSource({
    "src/redemptions.js": READ_THEN_WRITE.replace(
      'const points = Number.parseInt(req.body.points, 10);',
      `const points = Number.parseInt(req.body.points, 10);
        const claim = await pool.query(
          "INSERT INTO redemption_requests (request_key, member_id) VALUES ($1, $2) ON CONFLICT (request_key) DO NOTHING RETURNING id",
          [String(req.body.requestKey || ""), req.user.id]
        );
        if (claim.rowCount === 0) {
          return res.status(200).json({ replayed: true });
        }`
    )
  });
  assert.deepEqual(ofCategory(result, "race_condition_double_spend"), []);
});

test("a blind decrement with no prior read is not reported as a read-modify-write", async () => {
  const result = await scanSource({
    "src/counters.js": `
      const express = require("express");
      const router = express.Router();
      const { pool } = require("../lib/db");

      router.post("/counters", async (req, res) => {
        const step = Number.parseInt(req.body.step, 10);
        await pool.query("UPDATE counters SET stock_units = $1 WHERE id = $2", [0 - step, req.params.id]);
        res.json({ ok: true });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(ofCategory(result, "race_condition_double_spend"), []);
});
