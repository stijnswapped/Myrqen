const REPLACEMENTS = {
  "&": "&amp;",
  "<": "&lt;",
  ">": "&gt;",
  '"': "&quot;",
  "'": "&#39;",
};

/** Text-node encoder. Everything that reaches a template goes through this. */
export function entities(value) {
  return String(value ?? "").replace(/[&<>"']/g, (character) => REPLACEMENTS[character]);
}

/** Attribute encoder: returns the value *with* its quotes so callers cannot forget them. */
export function quoteAttr(value) {
  return `"${entities(value)}"`;
}

export function layout(title, body) {
  return `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>${entities(title)} — Sift</title>
    <link rel="stylesheet" href="/static/sift.css">
  </head>
  <body>
    <main class="shell">${body}</main>
  </body>
</html>`;
}
