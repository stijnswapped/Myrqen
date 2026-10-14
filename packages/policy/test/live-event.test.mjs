import { test } from "node:test";
import assert from "node:assert/strict";
import { SAFE_STATUS_CODES, assertLiveEventSafe, buildSafeEvent } from "../dist/index.js";
import { SHAPES } from "./shapes.mjs";

test("a built event carries only allowlisted fields and derived copy", () => {
  const event = buildSafeEvent({ reportId: "r1", type: "phase_started", phase: "discovery", safeCode: "MAPPING_APPLICATION" });
  assert.deepEqual(Object.keys(event).sort(), ["eventId", "message", "occurredAt", "phase", "reportId", "safeCode", "type"]);
  assert.equal(event.message, SAFE_STATUS_CODES.MAPPING_APPLICATION);
});

test("aggregate counts are permitted; anything else is refused", () => {
  const ok = buildSafeEvent({
    reportId: "r1",
    type: "aggregate_updated",
    aggregate: { candidateCount: 7, validatedCount: 3, high: 1 }
  });
  assert.equal(ok.aggregate.validatedCount, 3);

  assert.throws(
    () => assertLiveEventSafe({ eventId: "e", reportId: "r", type: "aggregate_updated", occurredAt: new Date().toISOString(), aggregate: { secretValue: 1 } }),
    /unsafe aggregate field/
  );
});

test("free-form progress text cannot be smuggled through the event", () => {
  const base = { eventId: "e", reportId: "r", type: "warning_safe", occurredAt: new Date().toISOString() };

  // Refused because it is free-form, not because it looks dangerous. Relying on
  // the scrubber alone left anything it did not recognise — a project's own
  // secret, a route, a filename — free to reach the cloud stream.
  assert.throws(() => assertLiveEventSafe({ ...base, message: "mapping the application" }), /allowlisted safeCode/);
  assert.throws(() => assertLiveEventSafe({ ...base, message: `found key ${SHAPES.stripeLive}` }), /allowlisted safeCode/);

  // A code that exists does not license arbitrary text beside it.
  assert.throws(
    () => assertLiveEventSafe({ ...base, safeCode: "SCAN_COMPLETE", message: "Scan complete, and here is why" }),
    /does not match the text its safeCode resolves to/
  );

  // The allowlisted pairing is accepted.
  assertLiveEventSafe({ ...base, safeCode: "SCAN_COMPLETE", message: SAFE_STATUS_CODES.SCAN_COMPLETE });

  assert.throws(() => buildSafeEvent({ reportId: "r1", type: "warning_safe", safeCode: "MADE_UP_CODE" }), /not allowlisted/);
});

test("unknown top-level fields are refused", () => {
  assert.throws(
    () =>
      assertLiveEventSafe({
        eventId: "e",
        reportId: "r",
        type: "phase_started",
        occurredAt: new Date().toISOString(),
        sourceSnippet: "const a = 1"
      }),
    /unsafe live event field/
  );
});

test("every allowlisted status code has calm, non-alarmist copy", () => {
  for (const [code, message] of Object.entries(SAFE_STATUS_CODES)) {
    assert.ok(message.length > 0 && message.length < 120, `${code} copy must be short`);
    assert.ok(!/!|fail!|danger|hacked/i.test(message) || code === "SCAN_FAILED", `${code} copy must stay calm`);
  }
});
