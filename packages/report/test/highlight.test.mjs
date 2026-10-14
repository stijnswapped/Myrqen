import { test } from "node:test";
import assert from "node:assert/strict";
import { CODE_STYLES, highlight, languageFor, renderCode } from "../dist/highlight.js";

/** What the source looks like once the three markup characters are neutralized. */
function escaped(source) {
  return source.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

/** Removes only the wrappers the highlighter adds, leaving the text it wrapped. */
function stripSpans(html) {
  return html.replace(/<span class="tok-[a-z]+">|<\/span>/g, "");
}

/** The rows of a rendered block, in order, minus the opening marker itself. */
function rowsOf(block) {
  return block.split('<span class="codeline"').slice(1);
}

test("markup in a snippet is escaped before the tokenizer can wrap it", () => {
  const payload = '<script>alert("xss")</script>';

  const source = `const t = '${payload}';`;
  const html = highlight(source, "javascript");
  assert.ok(!html.includes("<script"), "a script tag survived into the output");
  assert.ok(!html.includes("</script"), "a closing script tag survived into the output");
  assert.equal(stripSpans(html), escaped(source));

  // The plain fallback has no grammar to hide behind: it must escape too.
  const block = renderCode(payload, { filePath: "notes.txt" });
  assert.ok(!/<script/i.test(block));
  assert.ok(!/<\/script/i.test(block));

  // A file path is written into attributes, so its quotes have to go as well.
  const attacked = renderCode("ok", { filePath: 'a" onmouseover="alert(1)' });
  assert.ok(!attacked.includes('onmouseover="'), "an attribute value broke out of its quotes");
  assert.match(attacked, /&quot;/);
});

test("an escaped character is never split across two spans", () => {
  const html = highlight("if (a < b && c > d) return;", "javascript");
  assert.equal(stripSpans(html), "if (a &lt; b &amp;&amp; c &gt; d) return;");
  assert.ok(!html.includes("</span>lt;"), "an entity was cut in half and would render as literal &lt;");
  assert.ok(!html.includes("</span>amp;"));
});

test("highlighting only wraps text, it never changes it", () => {
  // Every case below is something that has broken a naive tokenizer: an
  // unterminated string, an unterminated comment, markup inside a string, a
  // raw string that must not interpolate, a comment marker inside a string.
  const cases = [
    ["javascript", 'const a = "<b>" + `x${y}` /* never closed'],
    ["javascript", "const s = 'unterminated"],
    ["typescript", "function f(x: string): void {}"],
    ["python", 'x = """open docstring\nstill inside'],
    ["go", "s := `raw ${not} interpolated`"],
    ["ruby", "puts 'it\\'s fine' # done"],
    ["php", "$name = $_GET['q']; // <b>"],
    ["sql", "SELECT * FROM t WHERE a = 'x -- not a comment'"],
    ["shell", 'curl "$HOST/api" # <not a tag>'],
    ["json", '{"a": 1, "b": "<i>&</i>"}'],
    ["plain", "anything at all <script>&"]
  ];

  for (const [language, source] of cases) {
    assert.equal(stripSpans(highlight(source, language)), escaped(source), `${language}: ${source}`);
  }
});

test("an unterminated string ends at its line, not at the end of the excerpt", () => {
  const source = 'const broken = "oops;\nconst after = 2;';
  const lines = highlight(source, "javascript").split("\n");

  assert.equal(lines.length, 2);
  assert.ok(lines[0].includes('<span class="tok-string">"oops;</span>'));
  assert.ok(!lines[1].includes("tok-string"), "the open quote swallowed the rest of the excerpt");
  assert.ok(lines[1].includes('<span class="tok-keyword">const</span>'));
});

test("a template literal survives a quote, an apostrophe, and markup inside it", () => {
  const html = highlight("const message = `it's \"quoted\" ${name}`;", "javascript");
  assert.ok(html.includes('<span class="tok-string">`it\'s "quoted" </span>'));
  assert.ok(html.includes('<span class="tok-punct">${</span>name'));
  assert.ok(html.endsWith('<span class="tok-punct">;</span>'), "the literal never closed");

  // Straight from the vuln-shop fixture: a template inside an interpolation
  // inside a template, with tags in both.
  const nested = highlight(
    'return html(response, 200, `<h1>Results for ${term}</h1><ul>${products.map((p) => `<li>${p.name}</li>`).join("")}</ul>`);',
    "javascript"
  );
  assert.ok(!nested.includes("<h1>"), "a tag from inside a string reached the output");
  assert.ok(nested.includes("&lt;h1&gt;"));
  assert.ok(nested.endsWith('<span class="tok-punct">);</span>'), "the nesting never unwound");
});

test("line numbers follow startLine", () => {
  const block = renderCode("alpha\nbravo\ncharlie", { startLine: 33 });
  for (const number of [33, 34, 35]) assert.ok(block.includes(`data-line="${number}"`), `line ${number}`);
  assert.ok(!block.includes('data-line="32"'));
  assert.ok(!block.includes('data-line="36"'));

  assert.ok(renderCode("one\ntwo").includes('data-line="1"'), "numbering starts at 1 by default");
  // A trailing newline ends the last line, it does not add an empty one.
  assert.ok(!renderCode("one\ntwo\n").includes('data-line="3"'));
});

test("the highlight range lands on the rows it names", () => {
  const rows = rowsOf(renderCode("one\ntwo\nthree\nfour", { startLine: 10, highlight: [11, 12] }));
  assert.equal(rows.length, 4);
  assert.ok(!rows[0].includes("data-flag"), "line 10 was flagged");
  assert.ok(rows[1].startsWith(' data-flag="true"'));
  assert.ok(rows[1].includes("two"));
  assert.ok(rows[2].startsWith(' data-flag="true"'));
  assert.ok(rows[2].includes("three"));
  assert.ok(!rows[3].includes("data-flag"), "line 13 was flagged");

  // A range given the other way round means the same two lines.
  const reversed = rowsOf(renderCode("one\ntwo\nthree", { highlight: [3, 2] }));
  assert.ok(!reversed[0].includes("data-flag"));
  assert.ok(reversed[1].includes("data-flag"));
  assert.ok(reversed[2].includes("data-flag"));

  // A range outside the excerpt emphasises nothing rather than guessing.
  assert.ok(!renderCode("one\ntwo", { startLine: 1, highlight: [40, 41] }).includes("data-flag"));
  assert.ok(!renderCode("one\ntwo").includes("data-flag"));
});

test("a flagged line is marked by more than colour", () => {
  const block = renderCode("one\ntwo", { highlight: [2, 2] });
  // Announced to a screen reader, from inside the gutter so it is never copied.
  assert.match(block, /<span class="codeline-flag">Flagged line 2\. <\/span>/);
  assert.match(CODE_STYLES, /border-left-color:var\(--codeFlag\)/, "no accent bar");
  assert.match(CODE_STYLES, /content:"▸"/, "no glyph");
});

test("the block is reachable and readable without a mouse or a network", () => {
  const block = renderCode("one\ntwo", { filePath: "src/db.js" });
  // A scrollable region has to be focusable or the overflow is unreachable.
  assert.match(block, /class="codeblock-scroll" tabindex="0"/);
  assert.match(block, /aria-label="Code excerpt from src\/db\.js"/);

  assert.ok(!/url\(|@import|https?:\/\//i.test(CODE_STYLES), "the styles must fetch nothing");
  assert.match(CODE_STYLES, /overflow-x:auto/, "the block, not the page, scrolls sideways");
  assert.match(CODE_STYLES, /user-select:none/, "the gutter would end up in a copied block");
  assert.match(CODE_STYLES, /content:attr\(data-line\)/, "line numbers must not be real text");
  assert.match(CODE_STYLES, /@media print/);
  assert.match(CODE_STYLES, /prefers-reduced-motion/);
  // The report's palette, not a second one.
  assert.match(CODE_STYLES, /var\(--text/);
  assert.match(CODE_STYLES, /var\(--focus/);
  // Monochrome: the lime that used to colour function names was brand drift.
  assert.doesNotMatch(CODE_STYLES, /B9F34A|185,243,74/i);
  assert.match(CODE_STYLES, /var\(--mono/);
});

test("the header names the file and the lines it is actually showing", () => {
  const block = renderCode("a\nb\nc", { startLine: 40, filePath: "src/db.js" });
  assert.match(block, /<span class="codeblock-path">src\/db\.js<\/span>/);
  assert.match(block, /lines 40-42/);
  assert.match(block, /JavaScript/, "the language was not derived from the path");

  assert.match(renderCode("a", { startLine: 7, filePath: "a.go" }), /line 7/);
  // Without a startLine there is no line range to claim.
  assert.ok(!renderCode("a\nb", { filePath: "src/db.js" }).includes("lines "));
});

test("languageFor reads the extension and tolerates an evidence location", () => {
  assert.equal(languageFor("src/db.js"), "javascript");
  // Evidence locations are written as "file:line".
  assert.equal(languageFor("src/routes/orders.ts:42"), "typescript");
  assert.equal(languageFor("src/routes/orders.ts:42:9"), "typescript");
  assert.equal(languageFor("package.json"), "json");
  assert.equal(languageFor("app/models/user.rb"), "ruby");
  assert.equal(languageFor("deploy/run.sh"), "shell");
  assert.equal(languageFor("C:\\app\\main.go"), "go");
  // Nothing is guessed at: an unknown or absent extension stays plain.
  assert.equal(languageFor("Makefile"), "plain");
  assert.equal(languageFor(".env"), "plain");
  assert.equal(languageFor(""), "plain");
});

test("an empty snippet renders no block at all", () => {
  assert.equal(renderCode(""), "", "an empty frame claims there was code to show");
  assert.equal(renderCode("   \n  "), "");
});
