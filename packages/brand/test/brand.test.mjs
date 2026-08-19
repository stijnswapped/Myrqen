import { test } from "node:test";
import assert from "node:assert/strict";
import { BRAND, makeBrand } from "../dist/index.js";

test("brand identity is frozen and complete", () => {
  assert.ok(Object.isFrozen(BRAND));
  for (const key of ["displayName", "cliName", "configDirectoryName", "deviceTokenPrefix", "reportSchemaVersion"]) {
    assert.ok(BRAND[key] && BRAND[key].length > 0, `${key} must be set`);
  }
});

test("alternate brand identity can be injected for rename safety tests", () => {
  const alt = makeBrand({ displayName: "Zebracorn", cliName: "zbc", configDirectoryName: "zbc" });
  assert.equal(alt.displayName, "Zebracorn");
  assert.equal(alt.cliName, "zbc");
  assert.equal(alt.reportSchemaVersion, BRAND.reportSchemaVersion);
});
