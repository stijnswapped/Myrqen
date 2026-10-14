"use strict";

const { app, ipcMain } = require("electron");
const { readFile, readdir, writeFile } = require("node:fs/promises");
const path = require("node:path");

const WORKSPACE_ID = /^[a-z0-9][a-z0-9-]{5,39}$/;
const MAX_NOTE_BYTES = 2 * 1024 * 1024;

function workspaceRoot() {
  return path.join(app.getPath("userData"), "workspaces");
}

function workspaceDir(workspaceId) {
  if (!WORKSPACE_ID.test(String(workspaceId))) throw new Error("that is not a workspace id");
  return path.join(workspaceRoot(), workspaceId);
}

ipcMain.handle("workspace:list", async (_event, workspaceId) => {
  const dir = workspaceDir(workspaceId);
  const entries = await readdir(dir, { withFileTypes: true });
  return entries.filter((entry) => entry.isFile()).map((entry) => entry.name);
});

ipcMain.handle("workspace:read", async (_event, workspaceId, relativePath) => {
  const dir = workspaceDir(workspaceId);
  const target = path.join(dir, relativePath);
  const contents = await readFile(target, "utf8");
  return { path: target, contents };
});

ipcMain.handle("workspace:write", async (_event, workspaceId, noteName, contents) => {
  const dir = workspaceDir(workspaceId);
  const body = String(contents ?? "");
  if (Buffer.byteLength(body, "utf8") > MAX_NOTE_BYTES) throw new Error("note is too large");
  const target = path.join(dir, `${path.basename(String(noteName), ".md")}.md`);
  await writeFile(target, body, "utf8");
  return { path: target, bytes: Buffer.byteLength(body, "utf8") };
});

module.exports = { workspaceDir };
