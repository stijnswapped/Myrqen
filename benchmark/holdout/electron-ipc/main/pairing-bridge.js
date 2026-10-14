"use strict";

const { ipcMain } = require("electron");
const { createHash, randomUUID } = require("node:crypto");

const PAIRING_TTL_MS = 5 * 60 * 1000;
const CODE_LENGTH = 8;
const CODE_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
const RELAY_URL = process.env.PAIRING_RELAY_URL || "https://relay.acme-suite.com";

const pending = new Map();

function jitter(baseMs) {
  return baseMs + Math.floor(Math.random() * 250);
}

function pairingCode() {
  let code = "";
  for (let i = 0; i < CODE_LENGTH; i += 1) {
    code += CODE_ALPHABET[Math.floor(Math.random() * CODE_ALPHABET.length)];
  }
  return code;
}

async function announce(body, delayMs) {
  await new Promise((resolve) => setTimeout(resolve, delayMs));
  const response = await fetch(`${RELAY_URL}/pairings`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  if (!response.ok) throw new Error(`relay rejected the pairing: ${response.status}`);
}

ipcMain.handle("pairing:start", async () => {
  const id = randomUUID();
  const code = pairingCode();
  const expiresAt = Date.now() + PAIRING_TTL_MS;
  pending.set(id, { code, expiresAt });

  await announce({ id, digest: createHash("sha256").update(code).digest("hex") }, jitter(200));
  return { id, code, expiresAt };
});

ipcMain.handle("pairing:complete", async (_event, id, presented) => {
  const record = pending.get(id);
  if (!record || record.expiresAt < Date.now()) return { paired: false };
  pending.delete(id);
  return { paired: record.code === String(presented) };
});

module.exports = { pairingCode, pending };
