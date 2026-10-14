import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fixedIn, scan } from "../dist/index.js";
import { parseLockfile } from "../dist/dependencies/lockfiles.js";
import { declaredRangeCertainlyAffected, inRange, parseVersion, compare } from "../dist/dependencies/semver.js";
import { ADVISORY_SNAPSHOT } from "../dist/dependencies/advisory-snapshot.js";

/**
 * The dependency check (ADR 019): installed versions from the lockfile, an offline
 * advisory snapshot, and a finding only where application code uses an affected export.
 *
 * The advisories used here are real records in the committed snapshot, looked up by id
 * so a snapshot refresh that drops one fails loudly rather than silently passing.
 */
async function project(files) {
  const root = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-deps-"));
  for (const [relative, contents] of Object.entries(files)) {
    const target = path.join(root, relative);
    await fs.mkdir(path.dirname(target), { recursive: true });
    await fs.writeFile(target, typeof contents === "string" ? contents : `${JSON.stringify(contents, null, 2)}\n`, "utf8");
  }
  return root;
}

async function dependencyCandidates(files) {
  const root = await project(files);
  try {
    const result = await scan({ repoRoot: root });
    return { candidates: result.candidates.filter((c) => c.category === "dependency_with_known_advisory"), coverage: result.coverage };
  } finally {
    await fs.rm(root, { recursive: true, force: true });
  }
}

const advisory = (id) => {
  const found = ADVISORY_SNAPSHOT.advisories.find((entry) => entry.id === id);
  assert.ok(found, `${id} must be in the snapshot`);
  return found;
};

const npmLock = (packages) => ({
  name: "app",
  lockfileVersion: 3,
  requires: true,
  packages: {
    "": { name: "app", dependencies: Object.fromEntries(Object.keys(packages).map((name) => [name, "*"])) },
    ...Object.fromEntries(Object.entries(packages).map(([name, version]) => [`node_modules/${name}`, { version }]))
  }
});

/* ------------------------------------------------------------ the snapshot */

test("the snapshot is sorted, carries curated reachability, and names its source", () => {
  assert.match(ADVISORY_SNAPSHOT.source, /OSV/);
  const entries = ADVISORY_SNAPSHOT.advisories;
  for (let index = 1; index < entries.length; index += 1) {
    const order = entries[index - 1].package.localeCompare(entries[index].package) || entries[index - 1].id.localeCompare(entries[index].id);
    assert.ok(order < 0, `${entries[index - 1].id} must sort before ${entries[index].id}`);
  }
  assert.deepEqual(advisory("GHSA-jf85-cpcp-j695").exports, ["defaultsDeep", "merge", "mergeWith"]);
  assert.equal(advisory("GHSA-xvch-5gv4-984h").package, "minimist");
});

/* ------------------------------------------------------------------ semver */

test("version comparison follows semver precedence, pre-releases included", () => {
  const v = (text) => parseVersion(text);
  assert.ok(compare(v("1.2.3"), v("1.2.10")) < 0);
  assert.ok(compare(v("1.0.0-alpha"), v("1.0.0")) < 0);
  assert.ok(compare(v("1.0.0-alpha.2"), v("1.0.0-alpha.10")) < 0);
  assert.ok(compare(v("1.0.0-alpha"), v("1.0.0-beta")) < 0);
  assert.ok(inRange(v("4.17.11"), { introduced: "0", fixed: "4.17.12" }));
  assert.ok(!inRange(v("4.17.12"), { introduced: "0", fixed: "4.17.12" }));
  assert.ok(inRange(v("0.0.4"), { introduced: "0", lastAffected: "0.0.4" }));
});

test("a declared range is affected only when it cannot resolve past the fix", () => {
  const ranges = [{ introduced: "0", fixed: "4.17.12" }];
  assert.equal(declaredRangeCertainlyAffected("4.17.11", ranges), "affected");
  assert.equal(declaredRangeCertainlyAffected("^4.17.11", ranges), "possibly");
  assert.equal(declaredRangeCertainlyAffected("~4.16.0", ranges), "affected");
  assert.equal(declaredRangeCertainlyAffected("^4.17.12", ranges), "no");
  assert.equal(declaredRangeCertainlyAffected("latest", ranges), "no");
  assert.equal(declaredRangeCertainlyAffected("workspace:*", ranges), "no");
});

/* --------------------------------------------------------------- lockfiles */

test("package-lock v3 and v1 are both read", () => {
  const v3 = parseLockfile("package-lock.json", JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { name: "x" },
      "node_modules/lodash": { version: "4.17.11" },
      "node_modules/a/node_modules/minimist": { version: "1.2.0", dev: true },
      "node_modules/@scope/pkg": { version: "2.0.0" }
    }
  }));
  assert.deepEqual(v3.map((p) => `${p.name}@${p.version}${p.dev ? ":dev" : ""}`).sort(), ["@scope/pkg@2.0.0", "lodash@4.17.11", "minimist@1.2.0:dev"]);
  const v1 = parseLockfile("package-lock.json", JSON.stringify({
    lockfileVersion: 1,
    dependencies: { qs: { version: "6.5.2", dependencies: { "side-channel": { version: "1.0.4" } } } }
  }));
  assert.deepEqual(v1.map((p) => `${p.name}@${p.version}`).sort(), ["qs@6.5.2", "side-channel@1.0.4"]);
});

test("pnpm v5, v6 and v9 package keys are read", () => {
  const v5 = parseLockfile("pnpm-lock.yaml", "lockfileVersion: 5.4\n\npackages:\n\n  /lodash/4.17.11:\n    resolution: {integrity: sha512-x}\n    dev: true\n\n  /@babel/core/7.0.0_react@18.2.0:\n    resolution: {integrity: sha512-y}\n");
  assert.deepEqual(v5.map((p) => `${p.name}@${p.version}${p.dev ? ":dev" : ""}`).sort(), ["@babel/core@7.0.0", "lodash@4.17.11:dev"]);
  const v6 = parseLockfile("pnpm-lock.yaml", "lockfileVersion: '6.0'\n\npackages:\n\n  /qs@6.5.2:\n    resolution: {integrity: sha512-x}\n\n  /@types/node@20.1.0(typescript@5.0.0):\n    dev: true\n");
  assert.deepEqual(v6.map((p) => `${p.name}@${p.version}`).sort(), ["@types/node@20.1.0", "qs@6.5.2"]);
  const v9 = parseLockfile("pnpm-lock.yaml", "lockfileVersion: '9.0'\n\npackages:\n\n  minimist@1.2.0:\n    resolution: {integrity: sha512-x}\n\n  '@scope/x@1.0.0':\n    resolution: {integrity: sha512-y}\n\nsnapshots:\n\n  minimist@1.2.0: {}\n");
  assert.deepEqual([...new Set(v9.map((p) => `${p.name}@${p.version}`))].sort(), ["@scope/x@1.0.0", "minimist@1.2.0"]);
});

test("yarn classic, yarn berry and bun.lock are read", () => {
  const classic = parseLockfile("yarn.lock", '# yarn lockfile v1\n\n\nlodash@^4.17.0, lodash@^4.17.11:\n  version "4.17.11"\n  resolved "https://registry/lodash"\n\n"@scope/pkg@^1.0.0":\n  version "1.2.0"\n');
  assert.deepEqual(classic.map((p) => `${p.name}@${p.version}`).sort(), ["@scope/pkg@1.2.0", "lodash@4.17.11"]);
  const berry = parseLockfile("yarn.lock", '__metadata:\n  version: 6\n\n"minimist@npm:^1.2.0":\n  version: 1.2.5\n  resolution: "minimist@npm:1.2.5"\n\n"app@workspace:.":\n  version: 0.0.0-use.local\n');
  assert.deepEqual(berry.map((p) => `${p.name}@${p.version}`), ["minimist@1.2.5"]);
  const bun = parseLockfile("bun.lock", '{\n  "lockfileVersion": 1,\n  "packages": {\n    "qs": ["qs@6.5.2", "", {}, "sha512-x"],\n  },\n}\n');
  assert.deepEqual(bun.map((p) => `${p.name}@${p.version}`), ["qs@6.5.2"]);
});

/* ------------------------------------------------------------ reachability */

test("a lockfile-pinned lodash whose merge is called is a finding at the call site", async () => {
  const { candidates } = await dependencyCandidates({
    "package.json": { name: "app", dependencies: { lodash: "^4.17.0", express: "^4.21.0" } },
    "package-lock.json": npmLock({ lodash: "4.17.11", express: "4.21.2" }),
    "src/settings.js": `import _ from "lodash";\nexport function apply(defaults, incoming) {\n  return _.merge({}, defaults, incoming);\n}\n`
  });
  const reached = candidates.filter((c) => c.ruleId === "dependency-advisory-reachable");
  assert.equal(reached.length, 1);
  assert.equal(reached[0].location.file, "src/settings.js");
  assert.equal(reached[0].location.line, 3);
  assert.equal(reached[0].severity, "high", "a critical advisory is capped at high: calling is necessary, not sufficient");
  assert.equal(reached[0].verification, "needs_review");
  assert.match(reached[0].summary, /GHSA-jf85-cpcp-j695/);
});

test("a reached call inside a route handler names the route", async () => {
  const { candidates } = await dependencyCandidates({
    "package.json": { name: "app", dependencies: { lodash: "4.17.11", express: "^4.21.0" } },
    "src/reports.js": `const express = require("express");\nconst _ = require("lodash");\nconst router = express.Router();\nrouter.post("/reports", (req, res) => {\n  res.json(_.merge({}, req.body.filters));\n});\nmodule.exports = router;\n`
  });
  const reached = candidates.find((c) => c.ruleId === "dependency-advisory-reachable");
  assert.ok(reached);
  assert.equal(reached.location.line, 5);
  assert.equal(reached.route, "POST /reports");
});

test("the same lodash with only unaffected functions called is listed as present, not reached", async () => {
  const { candidates } = await dependencyCandidates({
    "package.json": { name: "app", dependencies: { lodash: "^4.17.0" } },
    "package-lock.json": npmLock({ lodash: "4.17.11" }),
    "src/list.js": `const { chunk } = require("lodash");\nmodule.exports = (rows) => chunk(rows, 50);\n`
  });
  assert.equal(candidates.filter((c) => c.ruleId === "dependency-advisory-reachable").length, 0);
  const listed = candidates.find((c) => c.ruleId === "dependency-advisory");
  assert.ok(listed);
  assert.equal(listed.severity, "low");
  assert.equal(listed.location.file, "package.json");
  assert.match(listed.summary, /affected functions are not called/);
});

test("a subpath import counts as the export it is", async () => {
  const { candidates } = await dependencyCandidates({
    "package.json": { name: "app", dependencies: { lodash: "4.17.11" } },
    "src/defaults.js": `import defaultsDeep from "lodash/defaultsDeep";\nexport const withDefaults = (value) => defaultsDeep(value, { theme: "light" });\n`
  });
  const reached = candidates.find((c) => c.ruleId === "dependency-advisory-reachable");
  assert.ok(reached);
  assert.equal(reached.location.line, 1);
});

test("a manifest range that can resolve to the fix is not reported, and the coverage says why", async () => {
  const { candidates, coverage } = await dependencyCandidates({
    "package.json": { name: "app", dependencies: { lodash: "^4.17.11" } },
    "src/settings.js": `import _ from "lodash";\nexport const apply = (a, b) => _.merge(a, b);\n`
  });
  assert.equal(candidates.length, 0);
  assert.ok(coverage.notAssessed.some((note) => /No lockfile was found/.test(note)));
});

test("an exact pin with no import is the informational aggregate, at the manifest", async () => {
  const { candidates } = await dependencyCandidates({
    "package.json": { name: "app", dependencies: { lodash: "4.17.11", minimist: "1.2.0" } },
    "src/server.js": `import http from "node:http";\nhttp.createServer((req, res) => res.end("ok")).listen(4950);\n`
  });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].ruleId, "dependency-advisory");
  assert.equal(candidates[0].severity, "low");
  assert.match(candidates[0].summary, /declared but not imported/);
});

test("a development-only dependency that is not reached is informational", async () => {
  const { candidates } = await dependencyCandidates({
    "package.json": { name: "app", devDependencies: { minimist: "1.2.0" } },
    "src/index.js": `export const ok = true;\n`
  });
  assert.equal(candidates.length, 1);
  assert.equal(candidates[0].severity, "info");
});

test("a transitive package is never reported as reached through its parent", async () => {
  const { candidates } = await dependencyCandidates({
    "package.json": { name: "app", dependencies: { express: "^4.21.0" } },
    "package-lock.json": npmLock({ express: "4.21.2", qs: "6.5.2" }),
    "src/app.js": `import express from "express";\nconst app = express();\napp.get("/", (req, res) => res.send(String(req.query.q ?? "")));\nexport default app;\n`
  });
  assert.equal(candidates.filter((c) => c.ruleId === "dependency-advisory-reachable").length, 0);
  const listed = candidates.find((c) => c.ruleId === "dependency-advisory");
  assert.ok(listed);
  assert.match(listed.summary, /qs@6\.5\.2/);
  assert.match(listed.summary, /installed as a dependency of another package/);
});

test("a method-name match is reported at medium at most", async () => {
  const { candidates } = await dependencyCandidates({
    "package.json": { name: "app", dependencies: { express: "4.18.2" } },
    "src/app.js": `import express from "express";\nconst app = express();\napp.get("/out", (req, res) => res.redirect(req.query.to));\nexport default app;\n`
  });
  const reached = candidates.find((c) => c.ruleId === "dependency-advisory-reachable");
  assert.ok(reached);
  // The open-redirect advisory is rated medium, which is also the ceiling for a match
  // made by method name rather than by an imported export.
  assert.equal(reached.severity, "medium");
  assert.match(reached.summary, /matched by method name/);
});

test("the same project scanned twice produces identical dependency candidates", async () => {
  const files = {
    "package.json": { name: "app", dependencies: { lodash: "^4.17.0", minimist: "^1.2.0" } },
    "package-lock.json": npmLock({ lodash: "4.17.11", minimist: "1.2.0" }),
    "src/a.js": `import _ from "lodash";\nexport const t = (s) => _.template(s);\n`
  };
  const first = await dependencyCandidates(files);
  const second = await dependencyCandidates(files);
  assert.deepEqual(first.candidates, second.candidates);
});

test("no advisory value is fetched at scan time", async () => {
  const original = globalThis.fetch;
  let called = false;
  globalThis.fetch = async () => {
    called = true;
    throw new Error("network");
  };
  try {
    await dependencyCandidates({
      "package.json": { name: "app", dependencies: { lodash: "4.17.11" } },
      "src/a.js": `import _ from "lodash";\nexport const m = (a, b) => _.merge(a, b);\n`
    });
  } finally {
    globalThis.fetch = original;
  }
  assert.equal(called, false);
});

test("fixedIn is the first release outside every advisory range, read from the snapshot", () => {
  const lodash = ADVISORY_SNAPSHOT.advisories.filter((advisory) => advisory.package === "lodash");
  const outside = (text) => {
    const version = parseVersion(text);
    return lodash.every((advisory) => advisory.ranges.every((range) => !inRange(version, range)));
  };
  const fixed = fixedIn("lodash", "4.17.11");
  assert.ok(fixed, "lodash 4.17.11 has a published fix");
  assert.ok(outside(fixed), `${fixed} is outside every lodash range`);
  // It is the first such release among the fixes the snapshot names.
  const earlierFixes = lodash
    .flatMap((advisory) => advisory.ranges.map((range) => range.fixed))
    .filter((text) => text && compare(parseVersion(text), parseVersion("4.17.11")) > 0 && compare(parseVersion(text), parseVersion(fixed)) < 0);
  for (const text of earlierFixes) assert.ok(!outside(text), `${text} is still inside a range, so it is not the answer`);

  assert.equal(fixedIn("lodash", fixed), null, "a version outside every range needs no fix");
  assert.equal(fixedIn("not-a-watched-package", "1.0.0"), null);
  assert.equal(fixedIn("lodash", "not-a-version"), null);
});

test("a dependency finding's evidence states the release that fixes it", async () => {
  const { candidates } = await dependencyCandidates({ "package.json": { name: "app", dependencies: { minimist: "1.2.0" } } });
  const evidence = candidates.flatMap((candidate) => candidate.evidence).map((item) => item.description).join("\n");
  assert.match(evidence, new RegExp(`minimist@1\\.2\\.0: .*fixed in ${fixedIn("minimist", "1.2.0").replace(/\./g, "\\.")}`));
});
