import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import ts from "typescript";

/**
 * The browser-extension adapter, driven directly rather than through `scan()`.
 *
 * Every case is written as source here. A framework adapter that only fires on a
 * fixture it has already seen is worthless in a real repository, and a test that
 * reads the corpus cannot tell the difference.
 *
 * Three things are asserted for every shape, because an entry point that gets
 * any of them wrong is worse than no entry point at all: the address a reader
 * will see in the report, the bindings the taint model will trust as the
 * caller's, and the bindings it must not — a `sender` seeded by mistake turns
 * every correctly written origin check into a manufactured finding.
 */
const here = path.dirname(fileURLToPath(import.meta.url));
const built = path.join(here, "../dist/ast/frameworks/extension.js");

if (!existsSync(built)) {
  test.skip("the extension adapter needs a build: dist/ast/frameworks/extension.js is absent", () => {});
} else {
  const { extensionAdapter } = await import(pathToFileURL(built).href);

  const JAVASCRIPT = /\.[cm]?jsx?$/;

  function parsed(relativePath, text) {
    const scriptKind = JAVASCRIPT.test(relativePath) ? ts.ScriptKind.JS : ts.ScriptKind.TS;
    return {
      relativePath,
      absolutePath: `/repo/${relativePath}`,
      text,
      source: ts.createSourceFile(relativePath, text, ts.ScriptTarget.Latest, true, scriptKind),
      language: scriptKind === ts.ScriptKind.JS ? "JavaScript" : "TypeScript"
    };
  }

  /** What the engine would see: nothing at all unless the adapter claims the file. */
  function entriesOf(relativePath, text) {
    const file = parsed(relativePath, text);
    if (!extensionAdapter.applies(file)) return [];
    return extensionAdapter.detect(file);
  }

  const WORKER = "background/service-worker.js";
  const addresses = (entries) => entries.map((entry) => `${entry.method} ${entry.path}`);
  const seedNames = (entry) => (entry.seeds ?? []).map((seed) => seed.name);
  const originOf = (entry, name) => (entry.seeds ?? []).find((seed) => seed.name === name)?.origin;

  /* ------------------------------------------------ runtime.onMessage and its siblings */

  test("a runtime message listener is an ipc entry point on its own channel", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
          sendResponse({ ok: true, echo: message });
        });
      `
    );
    assert.equal(entry.framework, "extension");
    assert.equal(entry.kind, "ipc");
    assert.deepEqual(addresses([entry]), ["MESSAGE runtime.onMessage"]);
    assert.ok(entry.node, "the handler body is attached so taint has something to analyse");
  });

  test("the message is seeded and the browser's own arguments are declared trusted", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
          sendResponse(handle(message, sender.id));
        });
      `
    );
    assert.deepEqual(seedNames(entry), ["message"]);
    assert.equal(originOf(entry, "message"), "message (sent by a content script or another extension)");
    assert.deepEqual(entry.trustedParameters, ["sender", "sendResponse"]);
  });

  test("an external listener says the caller may be any web page, because that is a different boundary", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
          sendResponse(dispatch(message));
        });
      `
    );
    assert.deepEqual(addresses([entry]), ["MESSAGE runtime.onMessageExternal"]);
    assert.equal(originOf(entry, "message"), "message (sent by a web page or another extension)");
    assert.deepEqual(entry.trustedParameters, ["sender", "sendResponse"]);
  });

  test("a user-script listener names the user script as the sender", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        chrome.runtime.onUserScriptMessage.addListener((message, sender, sendResponse) => {
          sendResponse(dispatch(message));
        });
      `
    );
    assert.deepEqual(addresses([entry]), ["MESSAGE runtime.onUserScriptMessage"]);
    assert.equal(originOf(entry, "message"), "message (sent by a user script)");
  });

  test("the Firefox namespace is the same API and is recognised identically", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        browser.runtime.onMessage.addListener((request, sender) => {
          return Promise.resolve(handle(request));
        });
      `
    );
    assert.deepEqual(addresses([entry]), ["MESSAGE runtime.onMessage"]);
    assert.deepEqual(seedNames(entry), ["request"]);
    assert.deepEqual(entry.trustedParameters, ["sender"]);
  });

  test("a cross-browser namespace alias resolves to the same channel", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        const api = globalThis.browser ?? globalThis.chrome;
        api.runtime.onMessage.addListener((message) => handle(message));
      `
    );
    assert.deepEqual(addresses([entry]), ["MESSAGE runtime.onMessage"]);
    assert.deepEqual(seedNames(entry), ["message"]);
  });

  test("a destructured namespace member resolves to the same channel", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        const { runtime } = chrome;
        runtime.onMessageExternal.addListener((message) => handle(message));
      `
    );
    assert.deepEqual(addresses([entry]), ["MESSAGE runtime.onMessageExternal"]);
    assert.deepEqual(seedNames(entry), ["message"]);
  });

  test("a handler declared as a named function in the same file is resolved", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        function handleMessage(message, sender, sendResponse) {
          sendResponse(dispatch(message));
        }
        chrome.runtime.onMessage.addListener(handleMessage);
      `
    );
    assert.ok(ts.isFunctionDeclaration(entry.node));
    assert.deepEqual(seedNames(entry), ["message"]);
    assert.deepEqual(entry.trustedParameters, ["sender", "sendResponse"]);
  });

  test("a destructured message seeds every field it binds, since there is no root to name", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessageExternal.addListener(({ type, payload }, sender) => {
          run(type, payload);
        });
      `
    );
    assert.deepEqual(seedNames(entry), ["type", "payload"]);
    assert.equal(
      originOf(entry, "payload"),
      "payload (a field of a message sent by a web page or another extension)"
    );
  });

  test("a listener registered with no handler this file can see is still an address", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        import { handleMessage } from "./messages.js";
        chrome.runtime.onMessage.addListener(handleMessage);
      `
    );
    assert.deepEqual(addresses([entry]), ["MESSAGE runtime.onMessage"]);
    assert.equal(entry.seeds, undefined, "an unresolved handler must not be given invented seeds");
  });

  /* ------------------------------------------------------------------ the address */

  test("a handler that answers exactly one message type is addressed by that type", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
          if (message.type !== "syncTokens") return false;
          sendResponse(sync(message));
          return true;
        });
      `
    );
    assert.deepEqual(addresses([entry]), ["MESSAGE syncTokens"]);
  });

  test("a switch over one case is the same statement written the other way", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessage.addListener((message) => {
          switch (message.action) {
            case "openLog":
              return openLog(message);
            default:
              return undefined;
          }
        });
      `
    );
    assert.deepEqual(addresses([entry]), ["MESSAGE openLog"]);
  });

  test("a handler that answers several types keeps the channel name, because it has no single address", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessage.addListener((message) => {
          switch (message.type) {
            case "listProjects":
              return listProjects();
            case "buildLog":
              return buildLog(message);
            default:
              return undefined;
          }
        });
      `
    );
    assert.deepEqual(addresses([entry]), ["MESSAGE runtime.onMessage"]);
  });

  test("a dispatch through a table names no type, and the channel is what the report can honestly say", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessageExternal.addListener((message, sender, sendResponse) => {
          const command = commands[message.type];
          sendResponse(command ? command(message) : null);
        });
      `
    );
    assert.deepEqual(addresses([entry]), ["MESSAGE runtime.onMessageExternal"]);
  });

  /* --------------------------------------------------------- long-lived connections */

  test("a port message listener inside onConnect is the entry point, not the connect itself", () => {
    const found = entriesOf(
      WORKER,
      `
        chrome.runtime.onConnect.addListener((port) => {
          port.onMessage.addListener((message, replyPort) => {
            replyPort.postMessage(handle(message));
          });
        });
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE port.onMessage"]);
    assert.deepEqual(seedNames(found[0]), ["message"]);
    assert.equal(originOf(found[0], "message"), "message (sent by a content script or another extension)");
    assert.deepEqual(found[0].trustedParameters, ["replyPort"]);
  });

  test("an external connection carries the web-page boundary down to its port messages", () => {
    const found = entriesOf(
      WORKER,
      `
        chrome.runtime.onConnectExternal.addListener(function (port) {
          port.onMessage.addListener(function (message) {
            port.postMessage(handle(message));
          });
        });
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE port.onMessage"]);
    assert.equal(originOf(found[0], "message"), "message (sent by a web page or another extension)");
  });

  test("a connection whose port is subscribed elsewhere is reported as a surface with no seeds", () => {
    const found = entriesOf(
      WORKER,
      `
        const ports = new Set();
        chrome.runtime.onConnect.addListener((port) => {
          ports.add(port);
          port.onDisconnect.addListener(() => ports.delete(port));
        });
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE runtime.onConnect"]);
    assert.equal(found[0].seeds, undefined, "no message was located, so nothing may be seeded");
    assert.deepEqual(found[0].trustedParameters, ["port"]);
  });

  test("a port the extension opened itself is the other end of the pipe and is not claimed", () => {
    const found = entriesOf(
      WORKER,
      `
        const port = chrome.runtime.connect({ name: "sidebar" });
        port.onMessage.addListener((message) => render(message));
      `
    );
    assert.deepEqual(found, []);
  });

  /* -------------------------------------------------------------- webRequest */

  test("an intercepted request is caller data, because the visited page chose its URL", () => {
    const [entry] = entriesOf(
      WORKER,
      `
        chrome.webRequest.onBeforeRequest.addListener(
          (details) => ({ redirectUrl: rewrite(details.url) }),
          { urls: ["<all_urls>"] },
          ["blocking"]
        );
      `
    );
    assert.deepEqual(addresses([entry]), ["MESSAGE webRequest.onBeforeRequest"]);
    assert.deepEqual(seedNames(entry), ["details"]);
    assert.equal(originOf(entry, "details"), "details (details of an intercepted network request)");
  });

  test("the rest of the webRequest family is the same surface and is recognised too", () => {
    const found = entriesOf(
      WORKER,
      `
        chrome.webRequest.onHeadersReceived.addListener((details) => audit(details), { urls: ["<all_urls>"] });
        chrome.webRequest.onBeforeSendHeaders.addListener((details) => audit(details), { urls: ["<all_urls>"] });
      `
    );
    assert.deepEqual(addresses(found), [
      "MESSAGE webRequest.onHeadersReceived",
      "MESSAGE webRequest.onBeforeSendHeaders"
    ]);
    assert.deepEqual(seedNames(found[0]), ["details"]);
  });

  /* -------------------------------------------------- a plain service worker's message */

  test("a worker message event is an address, and the MessageEvent itself is never seeded", () => {
    const found = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessage.addListener((message) => handle(message));
        self.addEventListener("message", (event) => {
          if (event.origin !== TRUSTED) return;
          handle(event.data);
        });
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE runtime.onMessage", "MESSAGE serviceWorker.onMessage"]);
    const worker = found.find((entry) => entry.path === "serviceWorker.onMessage");
    assert.equal(worker.kind, "ipc");
    assert.equal(worker.seeds, undefined, "event.origin is the browser's, so the event may not be a seed");
  });

  test("the payload read off a message event is seeded under the name it was bound to", () => {
    const worker = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessage.addListener((message) => handle(message));
        self.addEventListener("message", (incoming) => {
          const { command, args } = incoming.data;
          run(command, args);
        });
      `
    ).find((found) => found.path === "serviceWorker.onMessage");
    assert.deepEqual(seedNames(worker), ["command", "args"]);
    assert.equal(
      originOf(worker, "command"),
      "command (incoming.data, the payload posted to this service worker)"
    );
  });

  test("a destructured message event seeds its data and nothing beside it", () => {
    const worker = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessage.addListener((message) => handle(message));
        self.onmessage = ({ data, origin }) => {
          if (origin !== TRUSTED) return;
          handle(data);
        };
      `
    ).find((found) => found.path === "serviceWorker.onMessage");
    assert.deepEqual(seedNames(worker), ["data"]);
  });

  /* ------------------------------------------------------------------- near misses */

  test("an install listener carries what the browser knows about the extension, not a payload", () => {
    const found = entriesOf(
      WORKER,
      `
        chrome.runtime.onInstalled.addListener((details) => {
          if (details.reason === "install") openOnboarding();
        });
        chrome.runtime.onMessage.addListener((message) => handle(message));
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE runtime.onMessage"]);
  });

  test("alarms, storage changes and tab updates are not message channels", () => {
    const found = entriesOf(
      WORKER,
      `
        chrome.alarms.onAlarm.addListener((alarm) => refresh(alarm.name));
        chrome.storage.onChanged.addListener((changes, area) => sync(changes, area));
        chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => note(tabId, changeInfo, tab));
        chrome.runtime.onMessage.addListener((message) => handle(message));
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE runtime.onMessage"]);
  });

  test("sending a message is not receiving one", () => {
    const found = entriesOf(
      WORKER,
      `
        chrome.runtime.sendMessage({ type: "ping" });
        chrome.tabs.sendMessage(tabId, { type: "ping" });
      `
    );
    assert.deepEqual(found, []);
  });

  test("an onMessage on somebody else's object is not the extension API", () => {
    const found = entriesOf(
      "src/gateway.ts",
      `
        const socket = createSocket();
        socket.onMessage.addListener((frame) => handle(frame));
      `
    );
    assert.deepEqual(found, []);
  });

  test("a Playwright handle called browser is not the extension namespace", () => {
    const found = entriesOf(
      "test/e2e.spec.ts",
      `
        const browser = await chromium.launch();
        const page = await browser.newPage();
        page.onMessage.addListener((frame) => handle(frame));
      `
    );
    assert.deepEqual(found, []);
  });

  test("a local bound to something else called browser reaches no extension member", () => {
    const found = entriesOf(
      "test/e2e.spec.ts",
      `
        const browser = launched;
        const handle = browser;
        handle.onMessage.addListener((frame) => record(frame));
      `
    );
    assert.deepEqual(found, []);
  });

  test("a progressive web app's service worker is not an extension worker", () => {
    const found = entriesOf(
      "public/sw.js",
      `
        self.addEventListener("message", (event) => {
          if (event.data.type === "SKIP_WAITING") self.skipWaiting();
        });
      `
    );
    assert.deepEqual(found, []);
  });

  test("a worker that only handles install and fetch registers no message channel", () => {
    const found = entriesOf(
      WORKER,
      `
        chrome.runtime.onMessage.addListener((message) => handle(message));
        self.addEventListener("install", () => self.skipWaiting());
        self.addEventListener("fetch", (event) => event.respondWith(fetch(event.request)));
      `
    );
    assert.deepEqual(addresses(found), ["MESSAGE runtime.onMessage"]);
  });

  test("the API named only inside a comment or a string claims nothing", () => {
    const found = entriesOf(
      "docs/notes.ts",
      `
        // chrome.runtime.onMessage.addListener is what the background worker uses.
        const documentation = "chrome.runtime.onMessageExternal.addListener(handler)";
        export const notes = documentation;
      `
    );
    assert.deepEqual(found, []);
  });
}
