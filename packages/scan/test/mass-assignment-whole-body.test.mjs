import { test } from "node:test";
import assert from "node:assert/strict";
import { massAssignmentWholeBody } from "../dist/rules/mass-assignment-whole-body.js";
import { runRules } from "./helpers/run-rules.mjs";

/**
 * Each rule is pinned by a defect and its correctly written sibling. The sources are
 * written inline for these tests and are named after nothing in any corpus.
 */
const run = (rule, source, file = "src/routes.js", extra = {}) => runRules([rule], source, file, extra);

test("a Mongoose create of the whole body on a user model is reported high", async () => {
  const found = await run(massAssignmentWholeBody, `
    import express from "express";
    import { User } from "../models/user.js";
    const router = express.Router();
    router.post("/users", async (req, res) => {
      const user = await User.create(req.body);
      res.status(201).json({ id: user.id, role: user.role });
    });
    export default router;
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].category, "mass_assignment");
  assert.equal(found[0].severity, "high");
});

test("the same create with named fields is not reported", async () => {
  const found = await run(massAssignmentWholeBody, `
    import express from "express";
    import { User } from "../models/user.js";
    const router = express.Router();
    router.post("/users", async (req, res) => {
      const { email, displayName } = req.body;
      const user = await User.create({ email, displayName });
      res.status(201).json({ id: user.id });
    });
    export default router;
  `);
  assert.equal(found.length, 0);
});

test("a Prisma update whose data is the parsed JSON body is reported, a Zod-parsed one is not", async () => {
  const found = await run(massAssignmentWholeBody, `
    import { prisma } from "@/lib/prisma";
    import { z } from "zod";
    const Patch = z.object({ displayName: z.string().max(80) });
    export async function PATCH(request, { params }) {
      const changes = await request.json();
      const account = await prisma.account.update({ where: { id: params.id }, data: changes });
      return Response.json(account);
    }
    export async function PUT(request, { params }) {
      const changes = Patch.parse(await request.json());
      const account = await prisma.account.update({ where: { id: params.id }, data: changes });
      return Response.json(account);
    }
  `, "app/api/accounts/[id]/route.ts");
  assert.equal(found.length, 1);
  assert.match(found[0].summary, /request\.json\(\)/);
});

test("a fetched Sequelize instance updated with the body is reported; Model.update limited by fields is not", async () => {
  const found = await run(massAssignmentWholeBody, `
    const { Project } = require("../models");
    module.exports = function mount(app) {
      app.put("/projects/:id", async (req, res) => {
        const project = await Project.findByPk(req.params.id);
        await project.update(req.body);
        res.json(project);
      });
      app.patch("/projects/:id", async (req, res) => {
        await Project.update(req.body, { where: { id: req.params.id }, fields: ["title", "summary"] });
        res.sendStatus(204);
      });
    };
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "PUT /projects/:id");
});

test("a route behind a validating middleware is left alone", async () => {
  const found = await run(massAssignmentWholeBody, `
    import express from "express";
    import { celebrate, Joi } from "celebrate";
    import { Order } from "../models/order.js";
    const router = express.Router();
    router.post("/orders", celebrate({ body: Joi.object({ sku: Joi.string() }) }), async (req, res) => {
      res.json(await Order.create(req.body));
    });
    export default router;
  `);
  assert.equal(found.length, 0);
});

test("a Drizzle insert of the whole body is reported", async () => {
  const found = await run(massAssignmentWholeBody, `
    import { db } from "../db/client.js";
    import { members } from "../db/schema.js";
    export async function addMember(req, res) {
      const [row] = await db.insert(members).values(req.body).returning();
      res.json(row);
    }
  `);
  assert.equal(found.length, 1);
});
