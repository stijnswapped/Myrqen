#!/usr/bin/env node
"use strict";

const { createWriteStream } = require("node:fs");
const { mkdir, writeFile } = require("node:fs/promises");
const path = require("node:path");
const { pipeline } = require("node:stream/promises");
const { Command } = require("commander");
const yauzl = require("yauzl");

const MANIFEST_ENTRY = "manifest.json";

function openArchive(archivePath) {
  return new Promise((resolve, reject) => {
    yauzl.open(archivePath, { lazyEntries: true, autoClose: true }, (err, zip) => {
      if (err) reject(err);
      else resolve(zip);
    });
  });
}

function readEntry(zip, entry) {
  return new Promise((resolve, reject) => {
    zip.openReadStream(entry, (err, stream) => {
      if (err) reject(err);
      else resolve(stream);
    });
  });
}

async function restore(archivePath, destination) {
  const root = path.resolve(destination);
  await mkdir(root, { recursive: true });

  const zip = await openArchive(archivePath);
  const restored = [];
  const skipped = [];

  for await (const entry of iterate(zip)) {
    if (entry.fileName.endsWith("/")) continue;

    if (entry.fileName === MANIFEST_ENTRY) {
      const stream = await readEntry(zip, entry);
      const chunks = [];
      for await (const chunk of stream) chunks.push(chunk);
      await writeFile(path.join(root, path.basename(MANIFEST_ENTRY)), Buffer.concat(chunks));
      continue;
    }

    const target = path.resolve(root, entry.fileName);
    if (target !== root && !target.startsWith(root + path.sep)) {
      skipped.push(entry.fileName);
      continue;
    }
    await mkdir(path.dirname(target), { recursive: true });
    await pipeline(await readEntry(zip, entry), createWriteStream(target));
    restored.push(entry.fileName);
  }

  return { restored, skipped };
}

async function* iterate(zip) {
  zip.readEntry();
  while (true) {
    const entry = await new Promise((resolve) => {
      zip.once("entry", resolve);
      zip.once("end", () => resolve(null));
    });
    if (!entry) return;
    yield entry;
    zip.readEntry();
  }
}

const program = new Command();
program
  .argument("<archive>", "snapshot downloaded from the workspace export API")
  .argument("<destination>", "directory to restore into")
  .action(async (archive, destination) => {
    const { restored, skipped } = await restore(archive, destination);
    process.stdout.write(`restored ${restored.length} file(s), skipped ${skipped.length}\n`);
  });

program.parseAsync(process.argv);
