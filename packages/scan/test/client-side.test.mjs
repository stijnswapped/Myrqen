import { test } from "node:test";
import assert from "node:assert/strict";
import { clientDomXss } from "../dist/rules/client-dom-xss.js";
import { clientOpenRedirect } from "../dist/rules/client-open-redirect.js";
import { runRules } from "./helpers/run-rules.mjs";

/**
 * Page code: the browser's own sources reaching HTML and navigation sinks.
 *
 * Every pair below is a defect and its correctly written sibling. A rule that only
 * passes the first half is a switch, not a rule.
 */
const xss = (source, file = "public/app.js") => runRules([clientDomXss], source, file);
const redirect = (source, file = "public/app.js") => runRules([clientOpenRedirect], source, file);

/* ---------------------------------------------------------------- DOM XSS */

test("the fragment written into innerHTML is reported", async () => {
  const found = await xss(`
    const banner = document.getElementById("welcome");
    const name = decodeURIComponent(location.hash.slice(1));
    banner.innerHTML = "<h2>Welcome back, " + name + "</h2>";
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].category, "dom_html_injection");
  assert.equal(found[0].severity, "high");
  assert.match(found[0].summary, /location\.hash/);
  assert.ok(found[0].taxonomy.includes("CWE-79"));
});

test("the same fragment written with textContent is not", async () => {
  const found = await xss(`
    const banner = document.getElementById("welcome");
    const name = decodeURIComponent(location.hash.slice(1));
    banner.textContent = "Welcome back, " + name;
  `);
  assert.equal(found.length, 0);
});

test("a query parameter passed through DOMPurify before innerHTML is not reported", async () => {
  const found = await xss(`
    import DOMPurify from "dompurify";
    const params = new URLSearchParams(window.location.search);
    const note = params.get("note") ?? "";
    document.querySelector("#note").innerHTML = DOMPurify.sanitize(note);
  `);
  assert.equal(found.length, 0);
});

test("a query parameter read through URLSearchParams into insertAdjacentHTML is reported", async () => {
  const found = await xss(`
    function renderNote() {
      const params = new URLSearchParams(window.location.search);
      const note = params.get("note") ?? "";
      document.querySelector("#notes").insertAdjacentHTML("beforeend", \`<li>\${note}</li>\`);
    }
    renderNote();
  `);
  assert.equal(found.length, 1);
  assert.match(found[0].title, /insertAdjacentHTML/);
});

test("a message listener that never checks the origin and renders its data is reported", async () => {
  // Named \`incoming\` on purpose: a parameter called \`event\` is already treated as
  // caller data by the request model, and dom-html-injection owns that spelling.
  const found = await xss(`
    window.addEventListener("message", (incoming) => {
      const preview = document.getElementById("preview");
      preview.innerHTML = incoming.data.html;
    });
  `);
  assert.equal(found.length, 1);
  assert.match(found[0].summary, /message/);
});

test("the same listener that pins event.origin first is not", async () => {
  const found = await xss(`
    const EDITOR_ORIGIN = "https://editor.example.com";
    window.onmessage = (incoming) => {
      if (incoming.origin !== EDITOR_ORIGIN) return;
      const preview = document.getElementById("preview");
      preview.innerHTML = incoming.data.html;
    };
  `);
  assert.equal(found.length, 0);
});

test("document.referrer written by document.write is reported", async () => {
  const found = await xss(`
    const from = document.referrer;
    document.write('<a href="' + from + '">Back</a>');
  `);
  assert.equal(found.length, 1);
});

test("a jQuery .html() of the window name is reported, a selector built from it is not", async () => {
  const found = await xss(`
    const label = window.name;
    $("#title").html(label);
    $("#" + label).addClass("active");
  `);
  assert.equal(found.length, 1);
  assert.match(found[0].title, /jQuery \.html/);
});

test("a fragment that passed an anchored pattern test is not reported", async () => {
  const found = await xss(`
    const tab = location.hash.slice(1);
    if (!/^[a-z-]+$/.test(tab)) {
      throw new Error("unknown tab");
    }
    document.getElementById("tab").innerHTML = "<span>" + tab + "</span>";
  `);
  assert.equal(found.length, 0);
});

test("a client component rendering a search parameter through dangerouslySetInnerHTML via the hash is reported", async () => {
  const found = await xss(
    `
    "use client";
    export function Announcement() {
      const fragment = typeof window === "undefined" ? "" : window.location.hash.slice(1);
      return <div dangerouslySetInnerHTML={{ __html: decodeURIComponent(fragment) }} />;
    }
  `,
    "components/announcement.tsx"
  );
  assert.equal(found.length, 1);
});

test("a fixed string written to innerHTML is not reported", async () => {
  const found = await xss(`
    const host = location.hostname;
    document.body.innerHTML = "<p>Loading…</p>";
  `);
  assert.equal(found.length, 0);
});

test("a value the request model already owns is left to that rule", async () => {
  // An extension listener's message is an entry-point seed, so dom-html-injection
  // reports it; this rule must not report the same line again.
  const found = await xss(`
    chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
      document.querySelector("#panel").innerHTML = message.note;
      sendResponse({ ok: true });
    });
  `);
  assert.equal(found.length, 0);
});

test("a fragment returned by a same-file helper and written into innerHTML is reported", async () => {
  const found = await xss(`
    function inviterFromLink() {
      const fragment = window.location.hash.slice(1);
      if (!fragment) return null;
      return decodeURIComponent(fragment.replace(/\\+/g, " "));
    }
    function render() {
      const inviter = inviterFromLink();
      document.getElementById("banner").innerHTML = "<h2>" + inviter + " invited you</h2>";
    }
    render();
  `);
  assert.equal(found.length, 1);
  assert.match(found[0].summary, /location\.hash/);
});

test("the same helper that keeps only safe characters is not", async () => {
  const found = await xss(`
    function inviterFromLink() {
      const fragment = window.location.hash.slice(1);
      return decodeURIComponent(fragment).replace(/[^\\w .-]/g, "");
    }
    document.getElementById("banner").innerHTML = "<h2>" + inviterFromLink() + " invited you</h2>";
  `);
  assert.equal(found.length, 0);
});

/* ---------------------------------------------------------- open redirect */

test("a sign-in page that honours ?next= with location.href is reported", async () => {
  const found = await redirect(`
    async function afterSignIn() {
      const next = new URLSearchParams(location.search).get("next");
      await fetch("/api/session", { method: "POST" });
      window.location.href = next || "/dashboard";
    }
  `);
  assert.equal(found.length, 1);
  assert.equal(found[0].category, "open_redirect");
  assert.equal(found[0].severity, "medium");
  assert.ok(found[0].taxonomy.includes("CWE-601"));
});

test("the same page that requires a same-origin path is not", async () => {
  const found = await redirect(`
    async function afterSignIn() {
      const next = new URLSearchParams(location.search).get("next") ?? "/dashboard";
      const target = new URL(next, location.origin);
      if (target.origin !== location.origin) {
        return location.assign("/dashboard");
      }
      window.location.href = target.pathname;
    }
  `);
  assert.equal(found.length, 0);
});

test("a destination with a fixed path prefix is not reported", async () => {
  const found = await redirect(`
    const id = new URLSearchParams(location.search).get("invoice");
    location.assign("/invoices/" + encodeURIComponent(id));
  `);
  assert.equal(found.length, 0);
});

test("a bare leading slash is not a guard", async () => {
  const found = await redirect(`
    const next = new URLSearchParams(location.search).get("next");
    location.replace("/" + next);
  `);
  assert.equal(found.length, 1);
});

test("reloading the current address without its fragment is not a redirect", async () => {
  const found = await redirect(`
    location.href = location.href.split("#")[0];
  `);
  assert.equal(found.length, 0);
});

test("the next/navigation hook's query reaching window.location is reported", async () => {
  const found = await redirect(
    `
    "use client";
    import { useSearchParams } from "next/navigation";
    export function Continue() {
      const searchParams = useSearchParams();
      const onClick = () => { window.location.assign(searchParams.get("returnTo")); };
      return <button onClick={onClick}>Continue</button>;
    }
  `,
    "components/continue.tsx"
  );
  assert.equal(found.length, 1);
});
