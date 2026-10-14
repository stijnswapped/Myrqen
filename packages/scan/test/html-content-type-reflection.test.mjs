import { test } from "node:test";
import assert from "node:assert/strict";
import { htmlContentTypeReflection } from "../dist/rules/html-content-type-reflection.js";
import { runRules } from "./helpers/run-rules.mjs";

/**
 * Each rule is pinned by a defect and its correctly written sibling. The sources are
 * written inline for these tests and are named after nothing in any corpus.
 */
const run = (rule, source, file = "src/routes.js", extra = {}) => runRules([rule], source, file, extra);

test("Hono c.html of a raw query value is reported", async () => {
  const found = await run(htmlContentTypeReflection, `
    import { Hono } from "hono";
    const app = new Hono();
    app.get("/preview", (c) => {
      const body = c.req.query("body") ?? "";
      return c.html(body);
    });
    export default app;
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].category, "reflected_cross_site_scripting");
});

test("the same value escaped first is not reported", async () => {
  const found = await run(htmlContentTypeReflection, `
    import { Hono } from "hono";
    import { escapeHtml } from "./escape.js";
    const app = new Hono();
    app.get("/preview", (c) => {
      const body = escapeHtml(c.req.query("body") ?? "");
      return c.html(body);
    });
    export default app;
  `);
  assert.equal(found.length, 0);
});

test("a text/html header followed by res.end of a query value is reported; text/plain is not", async () => {
  const found = await run(htmlContentTypeReflection, `
    const express = require("express");
    const app = express();
    app.get("/echo", (req, res) => {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      res.end(req.query.message);
    });
    app.get("/echo.txt", (req, res) => {
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      res.end(req.query.message);
    });
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "GET /echo");
});

test("a response-writing helper whose parameter happens to be called body is not reported", async () => {
  // The helper sends whatever its caller passes; the caller is where a missing
  // escape would be, and reflected-xss follows layout helpers back to it.
  const found = await run(htmlContentTypeReflection, `
    function page(response, status, body) {
      response.writeHead(status, { "content-type": "text/html; charset=utf-8" });
      response.end(body);
    }
    export { page };
  `);
  assert.equal(found.length, 0);
});

test("res.type('html').send of a body field is reported", async () => {
  const found = await run(htmlContentTypeReflection, `
    const express = require("express");
    const router = express.Router();
    router.post("/render", (req, res) => {
      res.type("html").send(req.body.snippet);
    });
    module.exports = router;
  `);
  assert.equal(found.length, 1);
});
