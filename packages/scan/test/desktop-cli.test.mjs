import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";

/**
 * The adapter is driven directly rather than through `scan()`, so these cases
 * hold whether or not the registry has been wired up yet. Every source is written
 * inline and none of it is copied from the benchmark corpus: an adapter that only
 * recognises a known fixture is worthless in a real repository.
 */
const dist = fileURLToPath(new URL("../dist/ast/frameworks/desktop-cli.js", import.meta.url));

if (!existsSync(dist)) {
  test("desktop-cli adapter", { skip: "run `npm run build -w @myrqen/scan` first" }, () => {});
} else {
  const ts = (await import("typescript")).default;
  const { desktopCliAdapter } = await import(dist);

  const parse = (text, relativePath = "src/main.ts") => ({
    relativePath,
    absolutePath: `/repo/${relativePath}`,
    text,
    source: ts.createSourceFile(
      relativePath,
      text,
      ts.ScriptTarget.Latest,
      true,
      /\.[cm]?js$/.test(relativePath) ? ts.ScriptKind.JS : ts.ScriptKind.TS
    ),
    language: /\.[cm]?js$/.test(relativePath) ? "JavaScript" : "TypeScript"
  });

  const detect = (text, relativePath) => {
    const file = parse(text, relativePath);
    assert.equal(desktopCliAdapter.applies(file), true, "the pre-filter must let this file through");
    return desktopCliAdapter.detect(file);
  };

  const seedNames = (entry) => (entry.seeds ?? []).map((seed) => seed.name).sort();

  /* ---------------- Electron IPC ---------------- */

  test("an ipcMain.handle channel seeds every argument after the event", () => {
    const [entry, ...rest] = detect(`
      import { ipcMain } from "electron";
      ipcMain.handle("workspace:open", async (event, folder, options) => {
        return read(folder, options);
      });
    `);
    assert.equal(rest.length, 0, "one registration is one entry point");
    assert.equal(entry.kind, "ipc");
    assert.equal(entry.method, "INVOKE");
    assert.equal(entry.path, "workspace:open");
    assert.deepEqual(seedNames(entry), ["folder", "options"]);
    assert.deepEqual(entry.trustedParameters, ["event"]);
    assert.equal(entry.seeds[0].origin, "folder (argument supplied by the renderer process)");
  });

  test("the IpcMainInvokeEvent is never seeded, however it is written", () => {
    const [entry] = detect(`
      import { ipcMain } from "electron";
      ipcMain.on("telemetry", function (evt, payload) {
        send(evt.sender.id, payload);
      });
    `);
    assert.deepEqual(entry.trustedParameters, ["evt"]);
    assert.deepEqual(seedNames(entry), ["payload"]);
  });

  test("a destructured event is trusted and a destructured payload is seeded", () => {
    const [entry] = detect(`
      const { ipcMain } = require("electron");
      ipcMain.handleOnce("file:write", ({ sender }, { target, contents }) => {
        write(target, contents, sender.id);
      });
    `, "src/main.js");
    assert.deepEqual(entry.trustedParameters, ["sender"]);
    assert.deepEqual(seedNames(entry), ["contents", "target"]);
  });

  test("a named handler passed by reference still gets its seeds", () => {
    const [entry] = detect(`
      import { ipcMain } from "electron";
      function importProject(event, archivePath) {
        return extract(archivePath);
      }
      ipcMain.handle("project:import", importProject);
    `);
    assert.deepEqual(seedNames(entry), ["archivePath"]);
    assert.equal(entry.node.kind, ts.SyntaxKind.FunctionDeclaration);
  });

  test("a computed channel is still an entry point, addressed as ipc", () => {
    const [entry] = detect(`
      import { ipcMain } from "electron";
      ipcMain.handle(CHANNELS.exportReport, (event, format) => build(format));
    `);
    assert.equal(entry.path, "ipc");
    assert.deepEqual(seedNames(entry), ["format"]);
  });

  test("a custom protocol handler seeds the request and not the callback", () => {
    const entries = detect(`
      import { protocol } from "electron";
      protocol.handle("workspace", (request) => respond(request.url));
      protocol.registerFileProtocol("asset", (request, callback) => {
        callback({ path: decodeURI(request.url.slice(8)) });
      });
    `);
    assert.deepEqual(entries.map((entry) => entry.path), ["workspace", "asset"]);
    assert.deepEqual(seedNames(entries[0]), ["request"]);
    assert.deepEqual(seedNames(entries[1]), ["request"]);
    assert.equal(entries[0].seeds[0].origin, "request (request to a custom protocol handler)");
  });

  /* ---------------- Command line ---------------- */

  test("a commander action seeds its arguments but not the Command object", () => {
    const [entry] = detect(`
      import { Command } from "commander";
      const program = new Command();
      program
        .command("publish")
        .argument("<archive>")
        .option("--registry <url>")
        .action((archive, options, command) => {
          upload(archive, options.registry);
        });
      program.parse();
    `, "bin/release.ts");
    assert.equal(entry.kind, "cli");
    assert.equal(entry.method, "RUN");
    assert.equal(entry.path, "publish");
    assert.deepEqual(seedNames(entry), ["archive", "options"]);
    assert.equal(entry.seeds[0].origin, "archive (command-line argument)");
  });

  test("a command stored in a variable keeps its own name", () => {
    const [entry] = detect(`
      const { program } = require("commander");
      const restore = program.command("restore <snapshot>");
      restore.action((snapshot) => run(snapshot));
    `, "bin/backup.cjs");
    assert.equal(entry.path, "restore");
    assert.deepEqual(seedNames(entry), ["snapshot"]);
  });

  test("a lone action parameter is data even when it is called cmd", () => {
    const [entry] = detect(`
      import sade from "sade";
      const prog = sade("runner");
      prog.command("exec <cmd>").action((cmd) => run(cmd));
      prog.parse(process.argv);
    `, "bin/runner.ts");
    assert.equal(entry.path, "exec");
    assert.deepEqual(seedNames(entry), ["cmd"]);
  });

  test("a yargs command handler is seeded, and its builder is not", () => {
    const entries = detect(`
      import yargs from "yargs";
      import { hideBin } from "yargs/helpers";
      yargs(hideBin(process.argv))
        .command("deploy <target>", "ship it", (builder) => builder.positional("target", {}), (argv) => {
          exec("scp " + argv.target);
        })
        .parse();
    `, "src/deploy.ts");
    const command = entries.find((entry) => entry.path === "deploy");
    assert.ok(command, "the yargs command is an entry point");
    assert.deepEqual(seedNames(command), ["argv"]);
    assert.ok(
      entries.every((entry) => !seedNames(entry).includes("builder")),
      "the builder receives the parser, not the user's arguments"
    );
  });

  test("the yargs module-object form is recognised", () => {
    const [entry] = detect(`
      import yargs from "yargs";
      yargs.command({
        command: "sync <remote>",
        describe: "sync",
        handler(argv) {
          fetchAll(argv.remote);
        }
      });
    `, "src/sync.ts");
    assert.equal(entry.path, "sync");
    assert.deepEqual(seedNames(entry), ["argv"]);
  });

  test("a bare process.argv read at module scope is an entry point", () => {
    const [entry] = detect(`
      #!/usr/bin/env node
      const [, , inputPath] = process.argv;
      require("node:child_process").execSync("tar -xf " + inputPath);
    `, "scripts/unpack.js");
    assert.equal(entry.kind, "cli");
    assert.equal(entry.path, "unpack");
    assert.deepEqual(seedNames(entry), ["inputPath"]);
    assert.equal(entry.node.kind, ts.SyntaxKind.SourceFile);
  });

  test("options read from the parser are command-line arguments too", () => {
    const [entry] = detect(`
      import { program } from "commander";
      program.option("--out <dir>");
      program.parse();
      const options = program.opts();
      write(options.out);
    `, "bin/build.ts");
    assert.deepEqual(seedNames(entry), ["options"]);
  });

  test("an oclif command seeds what this.parse hands back", () => {
    const [entry] = detect(`
      import { Command } from "@oclif/core";
      export default class Migrate extends Command {
        static id = "db:migrate";
        async run() {
          const { args, flags } = await this.parse(Migrate);
          exec("psql -f " + args.file);
        }
      }
    `, "src/commands/migrate.ts");
    assert.equal(entry.path, "db:migrate");
    assert.deepEqual(seedNames(entry), ["args", "flags"]);
  });

  /* ---------------- What must not be claimed ---------------- */

  test("a file that only declares something called action is not a CLI", () => {
    const file = parse(`
      export function action(input) {
        return dispatch({ type: "save", input });
      }
      store.action(({ payload }) => reduce(payload));
    `, "src/store.ts");
    assert.equal(desktopCliAdapter.applies(file), false);
    assert.deepEqual(desktopCliAdapter.detect(file), []);
  });

  test("an Express handler is left to the HTTP adapters", () => {
    const file = parse(`
      import express from "express";
      const app = express();
      app.get("/orders/:id", (req, res) => res.json(load(req.params.id)));
    `, "src/server.ts");
    assert.equal(desktopCliAdapter.applies(file), false);
  });

  test("a renderer file that only mentions ipcRenderer produces nothing", () => {
    const [entry] = detect(`
      import { ipcRenderer, ipcMain } from "electron";
      export const open = (folder) => ipcRenderer.invoke("workspace:open", folder);
    `, "src/preload.ts");
    assert.equal(entry, undefined, "invoking a channel is not registering one");
  });
}
