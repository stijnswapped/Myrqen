import { test } from "node:test";
import assert from "node:assert/strict";
import { locationHeaderRedirect } from "../dist/rules/location-header-redirect.js";
import { runRules } from "./helpers/run-rules.mjs";

/**
 * Each rule is pinned by a defect and its correctly written sibling. The sources are
 * written inline for these tests and are named after nothing in any corpus.
 */
const run = (rule, source, file = "src/routes.js", extra = {}) => runRules([rule], source, file, extra);

test("a Location header set from the query string is reported", async () => {
  const found = await run(locationHeaderRedirect, `
    import http from "node:http";
    http.createServer((req, res) => {
      const url = new URL(req.url, "http://localhost");
      const back = url.searchParams.get("back");
      res.writeHead(302, { Location: back });
      res.end();
    }).listen(4901);
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].category, "open_redirect");
  assert.ok(found[0].taxonomy.includes("CWE-601"));
});

test("a Location header pinned to a fixed path prefix is not", async () => {
  const found = await run(locationHeaderRedirect, `
    import http from "node:http";
    http.createServer((req, res) => {
      const url = new URL(req.url, "http://localhost");
      const id = url.searchParams.get("doc");
      res.writeHead(302, { Location: "/documents/" + encodeURIComponent(id) });
      res.end();
    }).listen(4901);
  `);
  assert.equal(found.length, 0);
});

test("a status-first Express redirect of a body field is reported, and a guarded one is not", async () => {
  const found = await run(locationHeaderRedirect, `
    const express = require("express");
    const app = express();
    app.post("/after-login", (req, res) => {
      res.redirect(303, req.body.returnTo);
    });
    app.post("/after-logout", (req, res) => {
      const target = req.body.returnTo;
      if (!target.startsWith("/") || target.startsWith("//")) {
        return res.redirect(303, "/");
      }
      res.redirect(303, target);
    });
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].route, "POST /after-login");
});

test("res.setHeader('Location', …) from the query is reported", async () => {
  const found = await run(locationHeaderRedirect, `
    export default function handler(req, res) {
      res.statusCode = 307;
      res.setHeader("Location", req.query.to);
      res.end();
    }
  `, "pages/api/go.js");
  assert.equal(found.length, 1);
});

test("a Location rebuilt from the request's own path and query is not reported", async () => {
  const found = await run(locationHeaderRedirect, `
    export function bustCache(req, res, expected) {
      const url = new URL(req.url || "", "http://localhost");
      url.searchParams.set("_v", expected);
      res.statusCode = 307;
      res.setHeader("location", \`\${url.pathname}\${url.search}\`);
      res.end();
    }
  `);
  assert.equal(found.length, 0);
});

test("a Location whose host comes from the query is still reported", async () => {
  const found = await run(locationHeaderRedirect, `
    export function hop(req, res) {
      const url = new URL(req.url || "", "http://localhost");
      res.setHeader("location", \`https://\${url.searchParams.get("host")}\${url.pathname}\`);
      res.end();
    }
  `);
  assert.equal(found.length, 1);
});
