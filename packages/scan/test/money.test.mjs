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
 * Deciding an amount without the word "charge" anywhere near it
 *
 * A quote endpoint returns the number the order is written from later, so a
 * caller who names their own unit price there buys at that price. The pair
 * below is the same handler twice, differing only in where the unit price
 * comes from, which is the only difference that matters.
 * ------------------------------------------------------------------ */

const LAMBDA_QUOTE = (unitPrice) => `
      "use strict";

      const { getCatalog } = require("../lib/catalog");
      const { requireClaims } = require("../lib/claims");
      const { ok, badRequest, conflict } = require("../lib/responses");

      const MAX_LINE_QUANTITY = 25;

      exports.handler = async (event) => {
        const claims = requireClaims(event);
        const body = JSON.parse(event.body || "{}");
        const lines = Array.isArray(body.lines) ? body.lines : [];
        if (lines.length === 0) return badRequest("a quote needs at least one line");

        const catalog = await getCatalog(claims.tenantId);
        const priced = [];
        let subtotalCents = 0;

        for (const line of lines) {
          const product = catalog.get(line.sku);
          if (!product) return badRequest("unknown sku");

          const quantity = Number.parseInt(line.quantity, 10);
          if (!Number.isInteger(quantity) || quantity < 1 || quantity > MAX_LINE_QUANTITY) {
            return badRequest("bad quantity");
          }
${unitPrice}
          subtotalCents += unitPriceCents * quantity;
          priced.push({ sku: product.sku, quantity, unitPriceCents });
        }

        return ok({ lines: priced, subtotalCents, currency: "EUR" });
      };
`;

test("a quote total built from a unit price the caller sent is reported", async () => {
  const result = await scanSource({
    "src/checkout-quote.js": LAMBDA_QUOTE(
      `          const unitPriceCents = Number(line.unitPriceCents != null ? line.unitPriceCents : product.unitPriceCents);`
    )
  });
  const found = ofCategory(result, "business_logic_price_manipulation");
  assert.equal(found.length, 1, "the quote is the price the order is written from");
  assert.match(found[0].summary, /unitPriceCents/);
});

test("the same quote pricing from the catalogue, with the sent price only compared, is not reported", async () => {
  const result = await scanSource({
    "src/renewal-quote.js": LAMBDA_QUOTE(
      `          if (line.unitPriceCents != null && Number(line.unitPriceCents) !== product.unitPriceCents) {
            return conflict("price has changed");
          }
          const unitPriceCents = product.unitPriceCents;`
    )
  });
  assert.deepEqual(
    ofCategory(result, "business_logic_price_manipulation"),
    [],
    "coercing the submitted price so it can be compared is not spending it"
  );
});

test("a caller-supplied line price multiplied into a total is reported without any settlement word", async () => {
  const result = await scanSource({
    "src/quotes.js": `
      const express = require("express");
      const router = express.Router();

      router.post("/quotes", async (req, res) => {
        const unitPriceCents = Number(req.body.unitPriceCents);
        const quantity = Number.parseInt(req.body.quantity, 10);
        const totalCents = unitPriceCents * quantity;
        res.json({ totalCents });
      });

      module.exports = router;
    `
  });
  const found = ofCategory(result, "business_logic_price_manipulation");
  assert.equal(found.length, 1, "a coerced price is still the caller's price");
  assert.match(found[0].summary, /unitPriceCents/);
});

test("a total multiplied out of the record the server loaded is not reported", async () => {
  const result = await scanSource({
    "src/quotes.js": `
      const express = require("express");
      const router = express.Router();
      const catalogue = require("../repositories/catalogue");

      router.post("/quotes", async (req, res) => {
        const product = await catalogue.findBySku(String(req.body.sku));
        const quantity = Number.parseInt(req.body.quantity, 10);
        const totalCents = product.unitPriceCents * quantity;
        res.json({ totalCents });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(
    ofCategory(result, "business_logic_price_manipulation"),
    [],
    "the quantity is the caller's to choose and the price is not the caller's"
  );
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

/* ------------------------------------------------------------------ *
 * Check-then-act on something that may only be spent once
 *
 * The arithmetic shape above needs a subtraction to see anything. These cases
 * have none: the value is the row's own state, and the defect is that the write
 * which consumes it does not repeat the condition the guard relied on. Each
 * firing case is paired with the version that carries the check into the WHERE
 * clause, because that predicate is the entire difference between the two and a
 * rule that cannot tell them apart would report every redemption endpoint ever
 * written.
 * ------------------------------------------------------------------ */

/** A Bun route that reads a gift card, checks it, and spends it. */
const GIFT_CARD_SERVER = (update, extra = "") => `
      import { Pool } from "pg";

      const pool = new Pool({ connectionString: Bun.env.DATABASE_URL });
      const REDEEM = /^\\/gift-cards\\/([^/]+)\\/redeem$/;

      Bun.serve({
        port: 3200,
        async fetch(request) {
          const { pathname } = new URL(request.url);
          const redeem = REDEEM.exec(pathname);
          if (redeem && request.method === "POST") {
            const body = await request.json();
            const amountCents = Number(body.amountCents);

            const found = await pool.query(
              "SELECT id, balance_cents, status FROM gift_cards WHERE code_hash = $1",
              [redeem[1]]
            );
            const card = found.rows[0];
            if (!card) return new Response("unknown card", { status: 404 });
            if (card.status !== "active") return new Response("already redeemed", { status: 409 });
            if (card.balance_cents < amountCents) return new Response("too little left", { status: 422 });

            ${update}
            ${extra}
            return Response.json({ redeemedCents: amountCents });
          }

          return new Response("Not found", { status: 404 });
        },
      });
`;

test("a gift card checked for an unspent status and then spent is reported against its own route", async () => {
  const result = await scanSource({
    "src/server.ts": GIFT_CARD_SERVER(`
            await pool.query("UPDATE gift_cards SET status = $2, balance_cents = $3 WHERE id = $1", [
              card.id,
              "spent",
              card.balance_cents - amountCents,
            ]);`)
  });
  const found = ofCategory(result, "race_condition_double_spend");
  assert.equal(found.length, 1, "the status the guard checked is not carried into the write");
  assert.equal(found[0].verification, "needs_review", "the interleaving cannot be observed statically");
  assert.match(found[0].summary, /status/);
  assert.match(found[0].route ?? "", /^POST \/gift-cards\//, "the reader needs the endpoint to probe it");
  assert.match(found[0].verificationPlan, /concurrent|at once|in flight/i);
});

test("the same redemption written as a conditional update is not reported", async () => {
  const result = await scanSource({
    "src/server.ts": GIFT_CARD_SERVER(
      `
            const spent = await pool.query(
              \`UPDATE gift_cards SET status = 'spent', balance_cents = balance_cents - $2
                 WHERE id = $1 AND status = 'active' AND balance_cents >= $2
               RETURNING balance_cents\`,
              [card.id, amountCents]
            );`,
      `
            if (spent.rowCount === 0) return new Response("already redeemed", { status: 409 });`
    )
  });
  assert.deepEqual(
    ofCategory(result, "race_condition_double_spend"),
    [],
    "the predicate carries the state that was checked, so one of two concurrent requests matches no row"
  );
});

test("naming an idempotency key without enforcing one does not clear the race", async () => {
  const result = await scanSource({
    "src/server.ts": GIFT_CARD_SERVER(
      `
            await pool.query("UPDATE gift_cards SET status = $2, balance_cents = $3 WHERE id = $1", [
              card.id,
              "spent",
              card.balance_cents - amountCents,
            ]);`,
      `
            await pool.query(
              "INSERT INTO gift_card_redemptions (card_id, amount_cents, idempotency_key) VALUES ($1, $2, $3)",
              [card.id, amountCents, request.headers.get("idempotency-key")]
            );`
    )
  });
  const found = ofCategory(result, "race_condition_double_spend");
  assert.equal(found.length, 1, "echoing the client's retry header into the receipt enforces nothing");
});

test("an idempotency key the database enforces is not reported", async () => {
  const result = await scanSource({
    "src/server.ts": GIFT_CARD_SERVER(
      `
            await pool.query("UPDATE gift_cards SET status = $2, balance_cents = $3 WHERE id = $1", [
              card.id,
              "spent",
              card.balance_cents - amountCents,
            ]);`,
      `
            await pool.query(
              \`INSERT INTO gift_card_redemptions (card_id, amount_cents, idempotency_key)
               VALUES ($1, $2, $3) ON CONFLICT (idempotency_key) DO NOTHING\`,
              [card.id, amountCents, request.headers.get("idempotency-key")]
            );`
    )
  });
  assert.deepEqual(ofCategory(result, "race_condition_double_spend"), []);
});

test("the same sequence with the row locked inside a transaction is not reported", async () => {
  const result = await scanSource({
    "src/server.ts": GIFT_CARD_SERVER(
      `
            await pool.query("UPDATE gift_cards SET status = $2, balance_cents = $3 WHERE id = $1", [
              card.id,
              "spent",
              card.balance_cents - amountCents,
            ]);`,
      `
            await pool.query("SELECT id FROM gift_cards WHERE id = $1 FOR UPDATE", [card.id]);`
    )
  });
  assert.deepEqual(ofCategory(result, "race_condition_double_spend"), []);
});

test("an optimistic-locking predicate on the row's version is not reported", async () => {
  const result = await scanSource({
    "src/server.ts": GIFT_CARD_SERVER(`
            await pool.query(
              "UPDATE gift_cards SET status = $2, balance_cents = $3 WHERE id = $1 AND row_version = $4",
              [card.id, "spent", card.balance_cents - amountCents, card.row_version]
            );`)
  });
  assert.deepEqual(
    ofCategory(result, "race_condition_double_spend"),
    [],
    "a version in the predicate is a compare-and-set written the other way round"
  );
});

test("a single-use invite read through a project query helper is reported", async () => {
  const result = await scanSource({
    "src/invites.js": `
      const express = require("express");
      const router = express.Router();
      const { one, run } = require("../lib/db");

      router.post("/invites/:code/accept", async (req, res) => {
        const invite = await one("SELECT id, redeemed, credit_cents FROM invites WHERE code_hash = $1", [
          hashOf(req.params.code),
        ]);
        if (!invite) return res.status(404).json({ error: "unknown invite" });
        if (invite.redeemed) return res.status(409).json({ error: "already accepted" });

        await run("UPDATE invites SET redeemed = true WHERE id = $1", [invite.id]);
        await run("INSERT INTO wallet_credits (user_id, amount_cents) VALUES ($1, $2)", [
          req.user.id,
          invite.credit_cents,
        ]);
        res.status(201).json({ creditedCents: invite.credit_cents });
      });

      module.exports = router;
    `
  });
  const found = ofCategory(result, "race_condition_double_spend");
  assert.equal(found.length, 1, "the read is a query whatever the project calls its helper");
  assert.match(found[0].summary, /redeemed/);
});

test("the same invite acceptance guarded by the update's own predicate is not reported", async () => {
  const result = await scanSource({
    "src/invites.js": `
      const express = require("express");
      const router = express.Router();
      const { one, run } = require("../lib/db");

      router.post("/invites/:code/accept", async (req, res) => {
        const invite = await one("SELECT id, redeemed, credit_cents FROM invites WHERE code_hash = $1", [
          hashOf(req.params.code),
        ]);
        if (!invite) return res.status(404).json({ error: "unknown invite" });
        if (invite.redeemed) return res.status(409).json({ error: "already accepted" });

        const accepted = await run("UPDATE invites SET redeemed = true WHERE id = $1 AND redeemed = false", [
          invite.id,
        ]);
        if (accepted.rowCount === 0) return res.status(409).json({ error: "already accepted" });

        await run("INSERT INTO wallet_credits (user_id, amount_cents) VALUES ($1, $2)", [
          req.user.id,
          invite.credit_cents,
        ]);
        res.status(201).json({ creditedCents: invite.credit_cents });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(ofCategory(result, "race_condition_double_spend"), []);
});

test("an ordinary lifecycle transition on a row worth nothing is not reported", async () => {
  const result = await scanSource({
    "src/documents.js": `
      const express = require("express");
      const router = express.Router();
      const { one, run } = require("../lib/db");

      router.post("/documents/:id/publish", async (req, res) => {
        const doc = await one("SELECT id, status, title FROM documents WHERE id = $1", [req.params.id]);
        if (!doc) return res.status(404).json({ error: "no such document" });
        if (doc.status !== "draft") return res.status(409).json({ error: "already published" });

        await run("UPDATE documents SET status = 'published', published_at = now() WHERE id = $1", [doc.id]);
        res.json({ published: true });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(
    ofCategory(result, "race_condition_double_spend"),
    [],
    "two editors who both publish a draft have raced and lost nothing"
  );
});

test("a status guard on a row nobody writes back is not reported", async () => {
  const result = await scanSource({
    "src/statements.js": `
      const express = require("express");
      const router = express.Router();
      const { one, run } = require("../lib/db");

      router.post("/gift-cards/:id/note", async (req, res) => {
        const card = await one("SELECT id, status, balance_cents FROM gift_cards WHERE id = $1", [req.params.id]);
        if (!card) return res.status(404).json({ error: "unknown card" });
        if (card.status !== "active") return res.status(409).json({ error: "card is closed" });

        await run("UPDATE gift_cards SET internal_note = $2 WHERE id = $1", [card.id, String(req.body.note || "")]);
        res.json({ ok: true });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(
    ofCategory(result, "race_condition_double_spend"),
    [],
    "the write changes a column the guard said nothing about, so it is not the transition the guard authorised"
  );
});

/* ------------------------------------------------------------------ *
 * The same defect in the dialects that do not write SQL
 *
 * Which query layer a project uses is an accident of its stack, and the race is
 * identical in all of them. These pairs exist so the rule cannot pass by knowing
 * one spelling: each one hides the check in a different place — a `where`
 * property, a Mongo filter argument, a `.where()` link in a builder chain — and
 * each fix puts the checked column into exactly that place.
 * ------------------------------------------------------------------ */

const PRISMA_REDEEM = (write) => `
      import { prisma } from "../lib/prisma";
      import { hashOf } from "../lib/codes";

      export async function POST(request: Request) {
        const { code, amountCents } = await request.json();

        const card = await prisma.giftCard.findUnique({
          where: { codeHash: hashOf(code) },
          select: { id: true, status: true, balanceCents: true },
        });

        if (!card) return Response.json({ error: "unknown card" }, { status: 404 });
        if (card.status !== "ACTIVE") return Response.json({ error: "already redeemed" }, { status: 409 });
        if (card.balanceCents < amountCents) return Response.json({ error: "too little left" }, { status: 422 });

        ${write}

        return Response.json({ redeemedCents: amountCents });
      }
`;

test("a query-builder update that changes the status it just checked is reported", async () => {
  const result = await scanSource({
    "app/api/gift-cards/redeem/route.ts": PRISMA_REDEEM(`
        await prisma.giftCard.update({
          where: { id: card.id },
          data: { status: "SPENT", balanceCents: card.balanceCents - amountCents },
        });`)
  });
  const found = ofCategory(result, "race_condition_double_spend");
  assert.equal(found.length, 1, "no SQL string appears anywhere, and the race is the same");
  assert.match(found[0].summary, /status/);
  assert.match(found[0].remediation, /filter|WHERE/i);
});

test("the same query-builder update filtered on the checked status is not reported", async () => {
  const result = await scanSource({
    "app/api/gift-cards/redeem/route.ts": PRISMA_REDEEM(`
        const spent = await prisma.giftCard.updateMany({
          where: { id: card.id, status: "ACTIVE" },
          data: { status: "SPENT", balanceCents: card.balanceCents - amountCents },
        });
        if (spent.count === 0) return Response.json({ error: "already redeemed" }, { status: 409 });`)
  });
  assert.deepEqual(ofCategory(result, "race_condition_double_spend"), []);
});

test("a document store that filters the consumption on identity alone is reported", async () => {
  const result = await scanSource({
    "src/vouchers.js": `
      const express = require("express");
      const router = express.Router();
      const { db } = require("../lib/mongo");

      router.post("/vouchers/:code/claim", async (req, res) => {
        const vouchers = db.collection("vouchers");
        const voucher = await vouchers.findOne({ codeHash: hashOf(req.params.code) });

        if (!voucher) return res.status(404).json({ error: "unknown voucher" });
        if (voucher.status !== "unclaimed") return res.status(409).json({ error: "already claimed" });

        await vouchers.updateOne(
          { _id: voucher._id },
          { $set: { status: "claimed", claimedBy: req.user.id, creditCents: voucher.creditCents } }
        );

        res.status(201).json({ creditedCents: voucher.creditCents });
      });

      module.exports = router;
    `
  });
  const found = ofCategory(result, "race_condition_double_spend");
  assert.equal(found.length, 1, "the filter matches the document whatever state it is now in");
  assert.match(found[0].summary, /status/);
});

test("the same document update whose filter repeats the state is not reported", async () => {
  const result = await scanSource({
    "src/vouchers.js": `
      const express = require("express");
      const router = express.Router();
      const { db } = require("../lib/mongo");

      router.post("/vouchers/:code/claim", async (req, res) => {
        const vouchers = db.collection("vouchers");
        const voucher = await vouchers.findOne({ codeHash: hashOf(req.params.code) });

        if (!voucher) return res.status(404).json({ error: "unknown voucher" });
        if (voucher.status !== "unclaimed") return res.status(409).json({ error: "already claimed" });

        const claimed = await vouchers.updateOne(
          { _id: voucher._id, status: "unclaimed" },
          { $set: { status: "claimed", claimedBy: req.user.id } }
        );
        if (claimed.modifiedCount === 0) return res.status(409).json({ error: "already claimed" });

        res.status(201).json({ creditedCents: voucher.creditCents });
      });

      module.exports = router;
    `
  });
  assert.deepEqual(ofCategory(result, "race_condition_double_spend"), []);
});

const DRIZZLE_REDEEM = (predicate, tail = "") => `
      import { and, eq } from "drizzle-orm";
      import { db } from "@/lib/db";
      import { giftCards } from "@/db/schema";

      export async function redeemGiftCard(formData: FormData) {
        const amountCents = Number(formData.get("amountCents") ?? 0);

        const card = await db.query.giftCards.findFirst({
          where: eq(giftCards.codeHash, String(formData.get("codeHash") ?? "")),
          columns: { id: true, status: true, balanceCents: true },
        });

        if (!card) return { ok: false as const, message: "Unknown card" };
        if (card.status !== "active") return { ok: false as const, message: "Already redeemed" };
        if (card.balanceCents < amountCents) return { ok: false as const, message: "Too little left" };

        const spent = await db
          .update(giftCards)
          .set({ status: "spent", balanceCents: card.balanceCents - amountCents })
          .where(${predicate})
          .returning({ id: giftCards.id });
        ${tail}
        return { ok: true as const, redeemedCents: amountCents };
      }
`;

test("a builder chain whose where link carries only the identifier is reported", async () => {
  const result = await scanSource({
    "src/actions/redeem.ts": DRIZZLE_REDEEM("eq(giftCards.id, card.id)")
  });
  const found = ofCategory(result, "race_condition_double_spend");
  assert.equal(found.length, 1, "the assignments and the predicate are separate links of one chain");
  assert.match(found[0].summary, /status/);
});

test("the same builder chain whose where link repeats the checked status is not reported", async () => {
  const result = await scanSource({
    "src/actions/redeem.ts": DRIZZLE_REDEEM(
      'and(eq(giftCards.id, card.id), eq(giftCards.status, "active"))',
      'if (spent.length === 0) return { ok: false as const, message: "Already redeemed" };'
    )
  });
  assert.deepEqual(ofCategory(result, "race_condition_double_spend"), []);
});

test("a lifecycle transition through a query builder on a row worth nothing is not reported", async () => {
  const result = await scanSource({
    "src/articles.ts": `
      import { prisma } from "../lib/prisma";

      export async function POST(request: Request) {
        const { articleId } = await request.json();

        const article = await prisma.article.findUnique({
          where: { id: articleId },
          select: { id: true, status: true, title: true },
        });

        if (!article) return Response.json({ error: "no such article" }, { status: 404 });
        if (article.status !== "DRAFT") return Response.json({ error: "already published" }, { status: 409 });

        await prisma.article.update({ where: { id: article.id }, data: { status: "PUBLISHED" } });

        return Response.json({ published: true });
      }
    `
  });
  assert.deepEqual(
    ofCategory(result, "race_condition_double_spend"),
    [],
    "nothing here is spent, so a duplicated transition costs nothing"
  );
});

test("a query-builder consumption inside a transaction is not reported", async () => {
  const result = await scanSource({
    "app/api/gift-cards/redeem/route.ts": PRISMA_REDEEM(`
        await prisma.$transaction(async (tx) => {
          await tx.giftCard.update({
            where: { id: card.id },
            data: { status: "SPENT", balanceCents: card.balanceCents - amountCents },
          });
        });`)
  });
  assert.deepEqual(ofCategory(result, "race_condition_double_spend"), []);
});

test("an update of a different model than the one that was checked is not reported", async () => {
  const result = await scanSource({
    "app/api/gift-cards/note/route.ts": PRISMA_REDEEM(`
        await prisma.auditEntry.update({
          where: { id: card.id },
          data: { status: "SEEN", balanceCents: card.balanceCents },
        });`)
  });
  assert.deepEqual(
    ofCategory(result, "race_condition_double_spend"),
    [],
    "the guard said nothing about the row this write changes"
  );
});

/* ------------------------------------- prepared handles and the check left behind */

/*
 * Two gaps found on held-out corpus 3, in the same pair of files.
 *
 * The statement lived in a module-level prepared handle, so reading argument 0 of
 * the call site found a number and concluded there was no statement — which
 * switched the rule off for every service that prepares its statements once.
 *
 * And the write settled its arithmetic in the database (`balance = balance - ?`),
 * which the rule treated as the fix. It is not: it makes the *decrement* atomic
 * while leaving the *authorising comparison* in application code. Both requests
 * pass `if (wallet.balance_cents < amount)` and both decrements apply.
 */

test("a prepared debit with no balance predicate is reported", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "tidewallet", version: "1.0.0", type: "module" }),
    "src/withdraw.ts": `import { Database } from "bun:sqlite";

const db = new Database("/var/lib/tide/tide.sqlite");
const readPurse = db.query<{ balance_cents: number }, [string]>(
  "select balance_cents from purses where id = ?"
);
const debitPurse = db.query("update purses set balance_cents = balance_cents - ? where id = ?");

export async function withdraw(request: Request, purseId: string): Promise<Response> {
  const body = await request.json();
  const amountCents = Number(body.amountCents);

  const purse = readPurse.get(purseId);
  if (!purse) return new Response("no purse", { status: 404 });
  if (purse.balance_cents < amountCents) return new Response("insufficient", { status: 402 });

  debitPurse.run(amountCents, purseId);
  return new Response(JSON.stringify({ ok: true }), { status: 200 });
}
`
  });
  const found = result.candidates.filter((c) => c.category === "race_condition_double_spend");
  assert.equal(found.length, 1, JSON.stringify(result.candidates.map((c) => [c.category, c.location.line])));
});

test("the same debit with the check repeated in the predicate is not reported", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "tidewallet", version: "1.0.0", type: "module" }),
    "src/withdraw-guarded.ts": `import { Database } from "bun:sqlite";

const db = new Database("/var/lib/tide/tide.sqlite");
const readPurse = db.query<{ balance_cents: number }, [string]>(
  "select balance_cents from purses where id = ?"
);
const debitPurse = db.query(
  "update purses set balance_cents = balance_cents - ? where id = ? and balance_cents >= ?"
);

export async function withdraw(request: Request, purseId: string): Promise<Response> {
  const body = await request.json();
  const amountCents = Number(body.amountCents);

  const purse = readPurse.get(purseId);
  if (!purse) return new Response("no purse", { status: 404 });
  if (purse.balance_cents < amountCents) return new Response("insufficient", { status: 402 });

  debitPurse.run(amountCents, purseId, amountCents);
  return new Response(JSON.stringify({ ok: true }), { status: 200 });
}
`
  });
  assert.deepEqual(
    result.candidates.filter((c) => c.category === "race_condition_double_spend").map((c) => c.location.line),
    [],
    "the predicate carries the decision into the write, so the row only changes when it still has the funds"
  );
});

test("an ordinary counter increment with no check to lose is not reported", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "tidewallet", version: "1.0.0", type: "module" }),
    "src/views.ts": `import { Database } from "bun:sqlite";

const db = new Database("/var/lib/tide/tide.sqlite");
const bumpViews = db.query("update articles set view_count = view_count + 1 where slug = ?");

export async function recordView(request: Request, slug: string): Promise<Response> {
  bumpViews.run(slug);
  return new Response(null, { status: 204 });
}
`
  });
  assert.deepEqual(
    result.candidates.filter((c) => c.category === "race_condition_double_spend").map((c) => c.location.line),
    [],
    "nothing was read and compared, so there is no decision for the write to lose"
  );
});

test("a fluent-builder read-modify-write on a balance is reported", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "tidevouchers", version: "1.0.0", type: "module" }),
    "src/actions/vouchers.ts": `import { eq } from "drizzle-orm";
import { db } from "../lib/db";
import * as schema from "../lib/schema";

export const vouchers = {
  redeem: async (input, context) => {
    const holder = context.locals.holder;

    const [voucher] = await db
      .select()
      .from(schema.vouchers)
      .where(eq(schema.vouchers.codeHash, input.code))
      .limit(1);
    if (!voucher) throw new Error("no such voucher");

    const applied = Math.min(voucher.balanceCents, input.totalCents);
    if (applied <= 0) throw new Error("nothing left");

    await db
      .update(schema.vouchers)
      .set({ balanceCents: voucher.balanceCents - applied })
      .where(eq(schema.vouchers.id, voucher.id));

    return { applied, holder: holder.id };
  }
};
`
  });
  const found = result.candidates.filter((c) => c.category === "race_condition_double_spend");
  assert.equal(found.length, 1, JSON.stringify(result.candidates.map((c) => [c.category, c.location.line])));
});

test("the same builder write with the balance repeated in the filter is not reported", async () => {
  const result = await scanSource({
    "package.json": JSON.stringify({ name: "tidevouchers", version: "1.0.0", type: "module" }),
    "src/actions/vouchers-guarded.ts": `import { and, eq, gte, sql } from "drizzle-orm";
import { db } from "../lib/db";
import * as schema from "../lib/schema";

export const vouchers = {
  redeem: async (input, context) => {
    const holder = context.locals.holder;

    const [voucher] = await db
      .select()
      .from(schema.vouchers)
      .where(eq(schema.vouchers.codeHash, input.code))
      .limit(1);
    if (!voucher) throw new Error("no such voucher");

    const applied = Math.min(voucher.balanceCents, input.totalCents);
    if (applied <= 0) throw new Error("nothing left");

    const changed = await db
      .update(schema.vouchers)
      .set({ balanceCents: voucher.balanceCents - applied })
      .where(and(eq(schema.vouchers.id, voucher.id), gte(schema.vouchers.balanceCents, applied)));

    return { applied, holder: holder.id, changed };
  }
};
`
  });
  assert.deepEqual(
    result.candidates.filter((c) => c.category === "race_condition_double_spend").map((c) => c.location.line),
    [],
    "the filter requires the balance to still be sufficient, so the row only changes when it is"
  );
});
