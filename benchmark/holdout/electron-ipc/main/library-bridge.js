"use strict";

const { app, ipcMain } = require("electron");
const { readFile, readdir, writeFile } = require("node:fs/promises");
const path = require("node:path");

const LIBRARY_ID = /^[a-z0-9][a-z0-9-]{5,39}$/;
const MAX_NOTE_BYTES = 2 * 1024 * 1024;

function libraryRoot() {
  return path.join(app.getPath("userData"), "libraries");
}

function libraryDir(libraryId) {
  if (!LIBRARY_ID.test(String(libraryId))) throw new Error("that is not a library id");
  return path.join(libraryRoot(), libraryId);
}

ipcMain.handle("library:list", async (_event, libraryId) => {
  const dir = libraryDir(libraryId);
  const entries = await readdir(dir, { withFileTypes: true });
  return entries.filter((entry) => entry.isFile()).map((entry) => entry.name);
});

ipcMain.handle("library:read", async (_event, libraryId, relativePath) => {
  const dir = libraryDir(libraryId);
  const target = path.resolve(dir, String(relativePath));
  if (target !== dir && !target.startsWith(dir + path.sep)) {
    throw new Error("that path is outside the library");
  }
  const contents = await readFile(target, "utf8");
  return { path: target, contents };
});

ipcMain.handle("library:write", async (_event, libraryId, noteName, contents) => {
  const dir = libraryDir(libraryId);
  const body = String(contents ?? "");
  if (Buffer.byteLength(body, "utf8") > MAX_NOTE_BYTES) throw new Error("note is too large");
  const target = path.join(dir, `${path.basename(String(noteName), ".md")}.md`);
  await writeFile(target, body, "utf8");
  return { path: target, bytes: Buffer.byteLength(body, "utf8") };
});

module.exports = { libraryDir };
