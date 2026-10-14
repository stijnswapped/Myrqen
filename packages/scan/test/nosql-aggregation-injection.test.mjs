import { test } from "node:test";
import assert from "node:assert/strict";
import { nosqlAggregationInjection } from "../dist/rules/nosql-aggregation-injection.js";
import { runRules } from "./helpers/run-rules.mjs";

/**
 * Each rule is pinned by a defect and its correctly written sibling. The sources are
 * written inline for these tests and are named after nothing in any corpus.
 */
const run = (rule, source, file = "src/routes.js", extra = {}) => runRules([rule], source, file, extra);

test("a query value in a $match stage is reported; a cast one is not", async () => {
  const found = await run(nosqlAggregationInjection, `
    import mongoose from "mongoose";
    const Order = mongoose.model("Order");
    export async function totals(req, res) {
      const rows = await Order.aggregate([
        { $match: { status: req.query.status } },
        { $group: { _id: "$customer", total: { $sum: "$amount" } } }
      ]);
      res.json(rows);
    }
    export async function totalsSafe(req, res) {
      const rows = await Order.aggregate([
        { $match: { status: String(req.query.status) } },
        { $group: { _id: "$customer", total: { $sum: "$amount" } } }
      ]);
      res.json(rows);
    }
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].category, "nosql_injection");
});

test("a whole body as the $match stage is reported, a path parameter is not", async () => {
  const found = await run(nosqlAggregationInjection, `
    import mongoose from "mongoose";
    const Event = mongoose.model("Event");
    export async function search(req, res) {
      res.json(await Event.aggregate([{ $match: req.body.filter }]));
    }
    export async function byTenant(req, res) {
      res.json(await Event.aggregate([{ $match: { tenant: req.params.tenant } }]));
    }
  `);
  assert.equal(found.length, 1);
});
