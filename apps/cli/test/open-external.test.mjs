/**
 * Opening a report or a URL hands a string to the platform's opener. On Windows
 * `cmd /c start` re-parses its arguments, so `&`, `|`, `^` in a path or URL would
 * become commands; the opener there is invoked without cmd, and targets carrying
 * characters cmd treats specially are refused outright.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import path from "node:path";
import { pathToFileURL } from "node:url";

const ROOT = path.resolve(import.meta.dirname, "..", "..", "..");
const open = await import(pathToFileURL(path.join(ROOT, "apps", "cli", "dist-tsc", "ui", "open.js")).href);

test("Windows opens through explorer.exe with an argv, never through cmd", () => {
  const invocation = open.openInvocation("C:\\repo\\.myrqen\\reports\\rpt_1\\report.html", "win32");
  assert.equal(invocation.command, "explorer.exe");
  assert.deepEqual(invocation.args, ["C:\\repo\\.myrqen\\reports\\rpt_1\\report.html"]);
  assert.notEqual(invocation.command.toLowerCase(), "cmd");
});

test("targets with characters cmd would interpret are refused on Windows", () => {
  for (const target of [
    "https://myrqen.cc/r/abc&calc.exe",
    "C:\\repo\\a|b\\report.html",
    "https://x.test/^x",
    "C:\\repo\\%PATH%\\report.html",
    "C:\\repo\\a\"b.html",
    "https://x.test/a\nb",
    "C:\\repo\\<x>.html",
    "C:\\repo\\(x)!.html"
  ]) {
    assert.equal(open.openInvocation(target, "win32"), null, JSON.stringify(target));
  }
});

test("macOS and Linux keep their own openers, with the target as one argument", () => {
  assert.deepEqual(open.openInvocation("/tmp/a b/report.html", "darwin"), { command: "open", args: ["/tmp/a b/report.html"] });
  assert.deepEqual(open.openInvocation("https://myrqen.cc/r/abc", "linux"), { command: "xdg-open", args: ["https://myrqen.cc/r/abc"] });
  assert.equal(open.openInvocation("-a Calculator", "darwin"), null, "a target that would read as an option is refused");
  assert.equal(open.openInvocation("", "linux"), null);
});
