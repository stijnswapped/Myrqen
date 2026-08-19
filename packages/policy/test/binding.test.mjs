import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import {
  bindingInteraction,
  bindingPaths,
  detachBinding,
  resolveRepositoryBinding,
  writePersonalBinding,
  writeTeamBinding
} from "../dist/index.js";

async function tempRepo({ git = true } = {}) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), "myrqen-binding-"));
  if (git) await fs.mkdir(path.join(dir, ".git", "info"), { recursive: true });
  return dir;
}

test("an unbound repository resolves to null so the CLI must ask", async () => {
  const repo = await tempRepo();
  assert.equal(await resolveRepositoryBinding(repo), null);
});

test("a personal binding is local, restrictive, and git-excluded", async () => {
  const repo = await tempRepo();
  const file = await writePersonalBinding(repo, { workspaceId: "w-personal", projectId: "p1", workspaceName: "Personal" });
  const stat = await fs.stat(file);
  assert.equal(stat.mode & 0o777, 0o600);

  const exclude = await fs.readFile(path.join(repo, ".git", "info", "exclude"), "utf8");
  assert.match(exclude, /\.myrqen\/local\.json/);

  const resolved = await resolveRepositoryBinding(repo);
  assert.equal(resolved.source, "personal_local");
  assert.equal(resolved.workspaceKind, "personal");
});

test("the exclude rule is written only once", async () => {
  const repo = await tempRepo();
  await writePersonalBinding(repo, { workspaceId: "w1", projectId: "p1" });
  await writePersonalBinding(repo, { workspaceId: "w1", projectId: "p1" });
  const exclude = await fs.readFile(path.join(repo, ".git", "info", "exclude"), "utf8");
  const occurrences = exclude.split("\n").filter((line) => line === ".myrqen/local.json").length;
  assert.equal(occurrences, 1);
});

test("a team binding file contains identifiers only and is safe to commit", async () => {
  const repo = await tempRepo();
  const file = await writeTeamBinding(repo, { workspaceId: "w-team", projectId: "p9" });
  const contents = JSON.parse(await fs.readFile(file, "utf8"));
  assert.deepEqual(Object.keys(contents).sort(), ["kind", "projectId", "version", "workspaceId"]);
  assert.ok(!JSON.stringify(contents).match(/token|secret|key/i));
});

test("a committed team binding wins over a local personal file", async () => {
  const repo = await tempRepo();
  await writePersonalBinding(repo, { workspaceId: "w-personal", projectId: "p1" });
  await writeTeamBinding(repo, { workspaceId: "w-team", projectId: "p9" });
  const resolved = await resolveRepositoryBinding(repo);
  assert.equal(resolved.source, "team_committed");
  assert.equal(resolved.workspaceId, "w-team");
});

test("a team-bound clone never silently falls back to Personal", async () => {
  const repo = await tempRepo();
  await writeTeamBinding(repo, { workspaceId: "w-team", projectId: "p9" });
  const resolved = await resolveRepositoryBinding(repo);
  assert.equal(resolved.workspaceKind, "team");
  assert.equal(resolved.workspaceId, "w-team");
});

test("a corrupt binding is an explicit error, never a guess", async () => {
  const repo = await tempRepo();
  const paths = bindingPaths(repo);
  await fs.mkdir(paths.dir, { recursive: true });
  await fs.writeFile(paths.team, '{"version":1,"kind":"team"}');
  await assert.rejects(() => resolveRepositoryBinding(repo), /not a valid Myrqen team binding/);
});

test("detach removes the requested binding files", async () => {
  const repo = await tempRepo();
  await writePersonalBinding(repo, { workspaceId: "w1", projectId: "p1" });
  await writeTeamBinding(repo, { workspaceId: "w2", projectId: "p2" });
  await detachBinding(repo, "team");
  assert.equal((await resolveRepositoryBinding(repo)).source, "personal_local");
  await detachBinding(repo, "both");
  assert.equal(await resolveRepositoryBinding(repo), null);
});

test("binding works in a non-git directory without failing", async () => {
  const repo = await tempRepo({ git: false });
  await writePersonalBinding(repo, { workspaceId: "w1", projectId: "p1" });
  assert.equal((await resolveRepositoryBinding(repo)).workspaceId, "w1");
});

test("interaction stays short with one option and explicit with several", () => {
  assert.equal(bindingInteraction({ workspaces: [{ id: "w1", name: "Personal", kind: "personal" }], repositoryHasTeamBinding: false }).mode, "single_option");
  assert.equal(
    bindingInteraction({
      workspaces: [
        { id: "w1", name: "Personal", kind: "personal" },
        { id: "w2", name: "Acme Team", kind: "team" }
      ],
      repositoryHasTeamBinding: false
    }).mode,
    "explicit_choice"
  );
  assert.equal(bindingInteraction({ workspaces: [], repositoryHasTeamBinding: true }).mode, "already_bound");
});
