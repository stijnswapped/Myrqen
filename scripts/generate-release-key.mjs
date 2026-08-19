#!/usr/bin/env node
/**
 * Generates an ed25519 release signing key pair. Run this offline and keep the
 * private key out of the repository and out of ordinary CI runners. The public
 * key is what clients pin.
 */
import fs from "node:fs/promises";
import { generateSigningKeyPair } from "../packages/updater/dist/index.js";

const keyId = process.argv[2] ?? `release-${new Date().toISOString().slice(0, 7)}`;
const { publicKeyPem, privateKeyPem } = generateSigningKeyPair();

await fs.writeFile(`${keyId}.private.pem`, privateKeyPem, { mode: 0o600 });
await fs.writeFile(`${keyId}.public.pem`, publicKeyPem, "utf8");

process.stdout.write(`key id: ${keyId}\n`);
process.stdout.write(`private key: ${keyId}.private.pem (mode 600, never commit this)\n`);
process.stdout.write(`public key:  ${keyId}.public.pem\n\n`);
process.stdout.write("Pin it in the client and the server with:\n");
process.stdout.write(
  `UPDATE_PUBLIC_KEYS='${JSON.stringify({ [keyId]: publicKeyPem })}'\n`
);
