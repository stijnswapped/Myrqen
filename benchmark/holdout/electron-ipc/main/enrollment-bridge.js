"use strict";

const { ipcMain } = require("electron");
const { createHash, randomBytes, randomUUID } = require("node:crypto");

const ENROLLMENT_TTL_MS = 5 * 60 * 1000;
const CODE_LENGTH = 8;
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const RELAY_URL = process.env.ENROLLMENT_RELAY_URL || "https://relay.acme-suite.com";

const pending = new Map();

function jitter(baseMs) {
  return baseMs + Math.floor(Math.random() * 250);
}

function enrollmentCode() {
  let code = "";
  while (code.length < CODE_LENGTH) {
    for (const byte of randomBytes(CODE_LENGTH * 2)) {
      if (byte >= 248) continue;
      code += CODE_ALPHABET[byte % CODE_ALPHABET.length];
      if (code.length === CODE_LENGTH) break;
    }
  }
  return code;
}

async function announce(body, delayMs) {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
  const response = await fetch(`${RELAY_URL}/enrollments`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error(`relay rejected the enrollment: ${response.status}`);
}

ipcMain.handle("enrollment:start", async () => {
  const id = randomUUID();
  const code = enrollmentCode();
  const expiresAt = Date.now() + ENROLLMENT_TTL_MS;
  pending.set(id, { code, expiresAt });

  await announce({ id, digest: createHash("sha256").update(code).digest("hex") }, jitter(200));
  return { id, code, expiresAt };
});

ipcMain.handle("enrollment:complete", async (_event, id, presented) => {
  const record = pending.get(id);
  if (!record || record.expiresAt < Date.now()) return { paired: false };
  pending.delete(id);
  return { paired: record.code === String(presented) };
});

module.exports = { enrollmentCode, pending };
