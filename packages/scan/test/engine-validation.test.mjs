import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { scan } from "../dist/index.js";

/**
 * Schema validators — zod, yup, joi, valibot — read field by field.
 *
 * A constrained field (a UUID, a number, an enum, an anchored safe pattern) can no longer
 * carry a quote or a separator, so the injection rules must stay silent on it. An open field
 * (`z.string()`, an email, a transform) is still the caller's text and must still be reported,
 * including when a guard validated the object it belongs to. Every positive has its near-miss.
 */
async function scanFiles(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-validation-"));
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

const PKG = JSON.stringify({
  name: "app",
  version: "1.0.0",
  type: "module",
  dependencies: { express: "^4.19.0", zod: "^3.23.0", yup: "^1.4.0", joi: "^17.13.0", valibot: "^0.31.0" }
});
const commands = (result) => result.candidates.filter((candidate) => candidate.category === "command_injection");

const zodRoute = (body, schema = "z.object({ id: z.string().uuid(), name: z.string().max(40), count: z.number().int() })") => `import express from "express";
import { exec } from "node:child_process";
import { z } from "zod";
const Body = ${schema};
export const router = express.Router();
router.post("/jobs", async (req, res) => {
${body}
  res.end();
});
`;

/* ---------- zod: the parsed value ---------- */

test("zod parse: a UUID field is constrained and stays silent", async () => {
  const result = await scanFiles({ "package.json": PKG, "src/route.js": zodRoute("  const data = Body.parse(req.body);\n  exec(`convert /in/${data.id}.png`);") });
  assert.equal(commands(result).length, 0);
});

test("zod parse: an open string field of the same schema is still reported", async () => {
  const result = await scanFiles({ "package.json": PKG, "src/route.js": zodRoute("  const data = Body.parse(req.body);\n  exec(`convert /in/${data.name}.png`);") });
  assert.equal(commands(result).length, 1);
});

test("zod parse, destructured: constrained fields clear, open fields do not", async () => {
  const silent = await scanFiles({ "package.json": PKG, "src/route.js": zodRoute("  const { id, count } = Body.parse(req.body);\n  exec(`convert /in/${id}-${count}.png`);") });
  assert.equal(commands(silent).length, 0);
  const reported = await scanFiles({ "package.json": PKG, "src/route.js": zodRoute("  const { id, name } = Body.parse(req.body);\n  exec(`convert /in/${id}-${name}.png`);") });
  assert.equal(commands(reported).length, 1);
});

test("zod parse inline: reading a constrained field off the call stays silent", async () => {
  const silent = await scanFiles({ "package.json": PKG, "src/route.js": zodRoute("  exec(`convert /in/${Body.parse(req.body).id}.png`);") });
  assert.equal(commands(silent).length, 0);
  const reported = await scanFiles({ "package.json": PKG, "src/route.js": zodRoute("  exec(`convert /in/${Body.parse(req.body).name}.png`);") });
  assert.equal(commands(reported).length, 1);
});

test("zod safeParse: `.data` is read field by field", async () => {
  const silent = await scanFiles({
    "package.json": PKG,
    "src/route.js": zodRoute("  const parsed = Body.safeParse(req.body);\n  if (!parsed.success) return res.status(400).end();\n  exec(`convert /in/${parsed.data.id}.png`);")
  });
  assert.equal(commands(silent).length, 0);
  const reported = await scanFiles({
    "package.json": PKG,
    "src/route.js": zodRoute("  const parsed = Body.safeParse(req.body);\n  if (!parsed.success) return res.status(400).end();\n  const { name } = parsed.data;\n  exec(`convert /in/${name}.png`);")
  });
  assert.equal(commands(reported).length, 1);
});

test("a whole-value schema clears the value it parsed", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/route.js": zodRoute("  const id = Body.parse(req.params.id);\n  exec(`convert /in/${id}.png`);", "z.string().uuid()")
  });
  assert.equal(commands(result).length, 0);
});

test("an anchored pattern with a safe alphabet constrains; an unanchored one does not", async () => {
  const silent = await scanFiles({
    "package.json": PKG,
    "src/route.js": zodRoute("  const { slug } = Body.parse(req.body);\n  exec(`convert /in/${slug}.png`);", "z.object({ slug: z.string().regex(/^[a-z0-9-]+$/) })")
  });
  assert.equal(commands(silent).length, 0);
  const reported = await scanFiles({
    "package.json": PKG,
    "src/route.js": zodRoute("  const { slug } = Body.parse(req.body);\n  exec(`convert /in/${slug}.png`);", "z.object({ slug: z.string().regex(/[a-z0-9-]+/) })")
  });
  assert.equal(commands(reported).length, 1);
});

test("a transform reopens a constrained field", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/route.js": zodRoute("  const { id } = Body.parse(req.body);\n  exec(`convert /in/${id}.png`);", "z.object({ id: z.string().uuid().transform((value) => value + req.query.x) })")
  });
  assert.equal(commands(result).length, 1);
});

/* ---------- a guard that validates the original object ---------- */

test("a safeParse guard no longer clears the whole request: an open field is still reported", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/route.js": zodRoute("  if (!Body.safeParse(req.body).success) return res.status(400).end();\n  exec(`convert /in/${req.body.name}.png`);")
  });
  assert.equal(commands(result).length, 1);
});

test("a safeParse guard clears the constrained field it validated", async () => {
  const result = await scanFiles({
    "package.json": PKG,
    "src/route.js": zodRoute("  if (!Body.safeParse(req.body).success) return res.status(400).end();\n  const { id } = req.body;\n  exec(`convert /in/${id}.png`);")
  });
  assert.equal(commands(result).length, 0);
});

test("a guard through a result binding validates its input", async () => {
  const silent = await scanFiles({
    "package.json": PKG,
    "src/route.js": zodRoute("  const check = Body.safeParse(req.body);\n  if (!check.success) return res.status(400).end();\n  exec(`convert /in/${req.body.id}.png`);")
  });
  assert.equal(commands(silent).length, 0);
  const reported = await scanFiles({
    "package.json": PKG,
    "src/route.js": zodRoute("  const check = Body.safeParse(req.body);\n  if (!check.success) return res.status(400).end();\n  exec(`convert /in/${req.body.name}.png`);")
  });
  assert.equal(commands(reported).length, 1);
});

test("a throwing parse used as a statement validates its input", async () => {
  const silent = await scanFiles({ "package.json": PKG, "src/route.js": zodRoute("  Body.parse(req.body);\n  exec(`convert /in/${req.body.id}.png`);") });
  assert.equal(commands(silent).length, 0);
  const reported = await scanFiles({ "package.json": PKG, "src/route.js": zodRoute("  Body.parse(req.body);\n  exec(`convert /in/${req.body.name}.png`);") });
  assert.equal(commands(reported).length, 1);
});

test("a guard whose schema cannot be read keeps the earlier behaviour", async () => {
  const route = `import express from "express";
import { exec } from "node:child_process";
import { Body } from "@acme/contracts";
export const router = express.Router();
router.post("/jobs", async (req, res) => {
  if (!Body.safeParse(req.body).success) return res.status(400).end();
  exec(\`convert /in/\${req.body.name}.png\`);
  res.end();
});
`;
  const result = await scanFiles({ "package.json": PKG, "src/route.js": route });
  assert.equal(commands(result).length, 0);
});

/* ---------- a schema declared in another module ---------- */

test("an imported schema is resolved through the module graph", async () => {
  const schemas = `import { z } from "zod";
export const JobBody = z.object({ id: z.string().uuid(), name: z.string() });
`;
  const route = (field) => `import express from "express";
import { exec } from "node:child_process";
import { JobBody } from "../schemas/job.js";
export const router = express.Router();
router.post("/jobs", async (req, res) => {
  const job = JobBody.parse(req.body);
  exec(\`convert /in/\${job.${field}}.png\`);
  res.end();
});
`;
  const silent = await scanFiles({ "package.json": PKG, "src/schemas/job.js": schemas, "src/routes/jobs.js": route("id") });
  assert.equal(commands(silent).length, 0);
  const reported = await scanFiles({ "package.json": PKG, "src/schemas/job.js": schemas, "src/routes/jobs.js": route("name") });
  assert.equal(commands(reported).length, 1);
});

test("a field schema declared beside the object, in the imported module, is followed", async () => {
  const schemas = `import { z } from "zod";
const Id = z.string().uuid();
export const JobBody = z.object({ id: Id, note: z.string() });
`;
  const route = `import express from "express";
import { exec } from "node:child_process";
import { JobBody } from "../schemas/job.js";
export const router = express.Router();
router.post("/jobs", async (req, res) => {
  const { id } = JobBody.parse(req.body);
  exec(\`convert /in/\${id}.png\`);
  res.end();
});
`;
  const result = await scanFiles({ "package.json": PKG, "src/schemas/job.js": schemas, "src/routes/jobs.js": route });
  assert.equal(commands(result).length, 0);
});

/* ---------- yup, joi, valibot ---------- */

test("yup: validate hands back the value, read field by field", async () => {
  const route = (field) => `import express from "express";
import { exec } from "node:child_process";
import * as yup from "yup";
const Body = yup.object({ page: yup.number().integer(), label: yup.string() });
export const router = express.Router();
router.post("/jobs", async (req, res) => {
  const body = await Body.validate(req.body);
  exec(\`convert /in/\${body.${field}}.png\`);
  res.end();
});
`;
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/route.js": route("page") })).length, 0);
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/route.js": route("label") })).length, 1);
});

test("joi: `{ value }` from validate is read field by field", async () => {
  const route = (field) => `import express from "express";
import { exec } from "node:child_process";
import Joi from "joi";
const Body = Joi.object({ code: Joi.string().alphanum(), note: Joi.string() });
export const router = express.Router();
router.post("/jobs", async (req, res) => {
  const { value, error } = Body.validate(req.body);
  if (error) return res.status(400).end();
  exec(\`convert /in/\${value.${field}}.png\`);
  res.end();
});
`;
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/route.js": route("code") })).length, 0);
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/route.js": route("note") })).length, 1);
});

test("valibot: v.parse(schema, input) with a piped refinement", async () => {
  const route = (field) => `import express from "express";
import { exec } from "node:child_process";
import * as v from "valibot";
const Body = v.object({ id: v.pipe(v.string(), v.uuid()), title: v.string() });
export const router = express.Router();
router.post("/jobs", async (req, res) => {
  const data = v.parse(Body, req.body);
  exec(\`convert /in/\${data.${field}}.png\`);
  res.end();
});
`;
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/route.js": route("id") })).length, 0);
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/route.js": route("title") })).length, 1);
});

/* ---------- not a validator ---------- */

test("a project object that merely has a parse method is not read as a schema", async () => {
  const route = `import express from "express";
import { exec } from "node:child_process";
const v = { number: () => ({ parse: (value) => value }) };
const Id = v.number();
export const router = express.Router();
router.post("/jobs", async (req, res) => {
  const id = Id.parse(req.body.id);
  exec(\`convert /in/\${id}.png\`);
  res.end();
});
`;
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/route.js": route })).length, 1);
});

test("yup cast does not validate refinements, so it clears nothing", async () => {
  const route = `import express from "express";
import { exec } from "node:child_process";
import * as yup from "yup";
const Body = yup.object({ id: yup.string().uuid() });
export const router = express.Router();
router.post("/jobs", async (req, res) => {
  const body = Body.cast(req.body);
  exec(\`convert /in/\${body.id}.png\`);
  res.end();
});
`;
  assert.equal(commands(await scanFiles({ "package.json": PKG, "src/route.js": route })).length, 1);
});

/* ---------- across a call boundary ---------- */

test("an open field of a parsed body crosses into a service; a constrained one does not", async () => {
  const service = `import { exec } from "node:child_process";
export function render(name) {
  exec(\`convert /in/\${name}.png\`);
}
`;
  const route = (field) => `import express from "express";
import { z } from "zod";
import { render } from "../services/render.js";
const Body = z.object({ id: z.string().uuid(), name: z.string() });
export const router = express.Router();
router.post("/jobs", async (req, res) => {
  const data = Body.parse(req.body);
  render(data.${field});
  res.end();
});
`;
  const reported = await scanFiles({ "package.json": PKG, "src/services/render.js": service, "src/routes/jobs.js": route("name") });
  assert.equal(commands(reported).length, 1);
  const silent = await scanFiles({ "package.json": PKG, "src/services/render.js": service, "src/routes/jobs.js": route("id") });
  assert.equal(commands(silent).length, 0);
});

test("a project helper that returns a whole-value schema parse clears its result", async () => {
  const helper = (schema) => `import { z } from "zod";
const Id = ${schema};
export function parseId(raw) {
  return Id.parse(raw);
}
`;
  const route = `import express from "express";
import { exec } from "node:child_process";
import { parseId } from "../lib/ids.js";
export const router = express.Router();
router.post("/jobs/:id", async (req, res) => {
  exec(\`convert /in/\${parseId(req.params.id)}.png\`);
  res.end();
});
`;
  const silent = await scanFiles({ "package.json": PKG, "src/lib/ids.js": helper("z.string().uuid()"), "src/routes/jobs.js": route });
  assert.equal(commands(silent).length, 0);
  const reported = await scanFiles({ "package.json": PKG, "src/lib/ids.js": helper("z.string()"), "src/routes/jobs.js": route });
  assert.equal(commands(reported).length, 1);
});

/* ---------- a number stays the caller's number ---------- */

test("a numeric schema field is still the caller's amount for the monetary rule", async () => {
  const route = `import express from "express";
import { z } from "zod";
const Body = z.object({ quantity: z.number() });
export const router = express.Router();
router.post("/checkout", async (req, res) => {
  const data = Body.parse(req.body);
  const total = 1999 * data.quantity;
  res.json({ total });
});
`;
  const result = await scanFiles({ "package.json": PKG, "src/route.js": route });
  assert.equal(result.candidates.filter((candidate) => candidate.ruleId === "unbounded-monetary-arithmetic").length, 1);
});
