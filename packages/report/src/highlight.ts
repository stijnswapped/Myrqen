/**
 * Code rendering for the report.
 *
 * The standalone HTML has to open with no network at all, and this package ships
 * zero runtime dependencies — a property worth keeping, because every dependency
 * added here would end up inlined in a file a developer opens to decide whether a
 * security finding is real. So the highlighter lives here, deliberately small.
 *
 * It is a lexer, not a parser. It never claims to understand the code; it wraps
 * the characters it can name and leaves everything else alone. Ordinary code
 * reads correctly, unusual code reads plainly, and nothing is ever dropped.
 */

export type TokenKind = "comment" | "string" | "number" | "keyword" | "function" | "punctuation";

interface Token {
  /** null means the text is written without a wrapper. */
  kind: TokenKind | null;
  /** Already escaped. The tokenizer never handles raw source. */
  text: string;
}

interface LanguageSpec {
  /** True for the fallback: an unknown grammar is not guessed at. */
  plain: boolean;
  lineComments: readonly string[];
  blockComment: readonly [string, string] | null;
  quotes: readonly string[];
  /** Backtick strings that interpolate `${...}` — JavaScript and TypeScript. */
  templates: boolean;
  /** Backtick strings that are raw: no escapes, no interpolation — Go. */
  rawBacktick: boolean;
  /** Triple-quoted strings that span lines — Python. */
  tripleQuotes: boolean;
  keywords: ReadonlySet<string>;
  caseInsensitiveKeywords: boolean;
}

const words = (list: string): ReadonlySet<string> => new Set(list.split(/\s+/).filter(Boolean));

const BASE: LanguageSpec = {
  plain: false,
  lineComments: [],
  blockComment: null,
  quotes: [],
  templates: false,
  rawBacktick: false,
  tripleQuotes: false,
  keywords: new Set<string>(),
  caseInsensitiveKeywords: false
};

/**
 * Only the languages Myrqen actually reports on. The TypeScript keyword list
 * stays narrow on purpose: `string` and `number` are ordinary variable names in
 * plenty of JavaScript, and mis-colouring real code costs more than the few
 * type annotations it would gain.
 */
const JAVASCRIPT: LanguageSpec = {
  ...BASE,
  lineComments: ["//"],
  blockComment: ["/*", "*/"],
  quotes: ['"', "'"],
  templates: true,
  keywords: words(`
    as async await break case catch class const continue debugger declare default delete do else enum export
    extends false finally for from function if implements import in infer instanceof interface keyof let
    namespace never new null of private protected public readonly return satisfies set static super switch
    this throw true try type typeof undefined unknown var void while with yield any
  `)
};

const PLAIN: LanguageSpec = { ...BASE, plain: true };

const LANGUAGES: Record<string, LanguageSpec> = {
  plain: PLAIN,
  javascript: JAVASCRIPT,
  typescript: JAVASCRIPT,
  json: { ...BASE, quotes: ['"'], keywords: words("true false null") },
  python: {
    ...BASE,
    lineComments: ["#"],
    quotes: ['"', "'"],
    tripleQuotes: true,
    keywords: words(`
      and as assert async await break class continue def del elif else except False finally for from global if
      import in is lambda None nonlocal not or pass raise return True try while with yield
    `)
  },
  go: {
    ...BASE,
    lineComments: ["//"],
    blockComment: ["/*", "*/"],
    quotes: ['"', "'"],
    rawBacktick: true,
    keywords: words(`
      append break cap case chan const continue default defer else error fallthrough false for func go goto if
      import interface iota len make map new nil package panic range recover return select struct switch true
      type var
    `)
  },
  ruby: {
    ...BASE,
    lineComments: ["#"],
    quotes: ['"', "'"],
    keywords: words(`
      alias and begin break case class def defined? do else elsif end ensure false for if in module next nil
      not or redo require require_relative rescue retry return self super then true undef unless until when
      while yield
    `)
  },
  php: {
    ...BASE,
    lineComments: ["//", "#"],
    blockComment: ["/*", "*/"],
    quotes: ['"', "'"],
    keywords: words(`
      abstract and array as break callable case catch class clone const continue declare default do echo else
      elseif empty enum extends final finally fn for foreach function global if implements include
      include_once instanceof insteadof interface isset list match namespace new null or print private
      protected public readonly require require_once return static switch throw trait true false try unset use
      var while xor yield
    `)
  },
  sql: {
    ...BASE,
    lineComments: ["--"],
    blockComment: ["/*", "*/"],
    quotes: ["'", '"'],
    caseInsensitiveKeywords: true,
    keywords: words(`
      all alter and as asc begin between by cascade case check column commit constraint create cross default
      delete desc distinct drop else end exists foreign from full group having if in index inner insert into
      is join key left like limit not null offset on or order outer primary references returning right
      rollback select set table then transaction union unique update values view when where with
    `)
  },
  shell: {
    ...BASE,
    lineComments: ["#"],
    quotes: ['"', "'"],
    keywords: words(`
      case declare do done elif else esac eval exec exit export fi for function if in local readonly return
      set shift source then trap unset until while
    `)
  }
};

const LANGUAGE_ALIASES: Record<string, string> = {
  js: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  jsx: "javascript",
  node: "javascript",
  ts: "typescript",
  tsx: "typescript",
  py: "python",
  python3: "python",
  golang: "go",
  rb: "ruby",
  sh: "shell",
  bash: "shell",
  zsh: "shell",
  console: "shell",
  psql: "sql",
  mysql: "sql",
  postgres: "sql",
  postgresql: "sql",
  text: "plain",
  txt: "plain"
};

const EXTENSION_LANGUAGES: Record<string, string> = {
  js: "javascript",
  mjs: "javascript",
  cjs: "javascript",
  jsx: "javascript",
  ts: "typescript",
  mts: "typescript",
  cts: "typescript",
  tsx: "typescript",
  json: "json",
  jsonc: "json",
  py: "python",
  pyi: "python",
  go: "go",
  rb: "ruby",
  rake: "ruby",
  gemspec: "ruby",
  php: "php",
  phtml: "php",
  sql: "sql",
  sh: "shell",
  bash: "shell",
  zsh: "shell"
};

/** Shown in the block header. A language nobody named is not announced at all. */
const LANGUAGE_LABELS: Record<string, string> = {
  javascript: "JavaScript",
  typescript: "TypeScript",
  json: "JSON",
  python: "Python",
  go: "Go",
  ruby: "Ruby",
  php: "PHP",
  sql: "SQL",
  shell: "Shell",
  plain: ""
};

const CLASS_FOR: Record<TokenKind, string> = {
  comment: "tok-comment",
  string: "tok-string",
  number: "tok-number",
  keyword: "tok-keyword",
  function: "tok-function",
  punctuation: "tok-punct"
};

const ENTITIES = ["&amp;", "&lt;", "&gt;"] as const;
// No "&", "<" or ">" here: escaping has already turned all three into
// entities, which are matched whole a step earlier.
const PUNCTUATION = new Set("{}[]()!#%*+,-./:;=?@^|~\\".split(""));
const NUMBER = /(?:0[xXbBoO][0-9A-Fa-f_]+|\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?)/y;
const IDENTIFIER = /[A-Za-z_$][A-Za-z0-9_$]*/y;
/** Interpolation can nest. Past this depth the rest is treated as string text. */
const TEMPLATE_DEPTH_LIMIT = 8;

/**
 * Escaping happens before anything else touches the source, and it is the only
 * place markup is neutralised. Afterwards the text contains no `<` and no `>`,
 * and every `&` begins exactly one of three entities — the invariant the
 * tokenizer relies on to consume entities whole. Split one across two spans and
 * the browser stops seeing an entity at all: the reader gets the literal text
 * `&lt;` where the code said `<`.
 *
 * Quotes are deliberately left intact. The tokenizer needs them to find string
 * boundaries, and token text is only ever written as element content, never into
 * an attribute value, so a quote there cannot escape anything.
 */
function escapeCode(source: string): string {
  return source.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

/** For attribute values, where a quote would end the attribute. */
function escapeAttribute(value: string): string {
  return escapeCode(String(value ?? "")).replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function normalizeSource(source: string): string {
  return String(source ?? "").replace(/\r\n?/g, "\n");
}

function entityAt(escaped: string, index: number): string | null {
  if (escaped.charAt(index) !== "&") return null;
  return ENTITIES.find((entity) => escaped.startsWith(entity, index)) ?? null;
}

function isCallSite(escaped: string, from: number): boolean {
  let index = from;
  while (index < escaped.length && (escaped.charAt(index) === " " || escaped.charAt(index) === "\t")) index += 1;
  return escaped.charAt(index) === "(";
}

/** Resolves an alias or an unknown name to a grammar we actually implement. */
export function normalizeLanguage(language: string | undefined): string {
  const name = String(language ?? "").trim().toLowerCase();
  const resolved = LANGUAGE_ALIASES[name] ?? name;
  return resolved in LANGUAGES ? resolved : "plain";
}

/**
 * Evidence locations are written as `src/db.js:33`, so a trailing position is
 * stripped before the extension is read; without that, every located snippet
 * would fall back to plain. An extension we do not implement stays plain rather
 * than being guessed at.
 */
export function languageFor(filePath: string): string {
  const name = String(filePath ?? "").split(/[\\/]/).pop() ?? "";
  const withoutPosition = name.replace(/:\d+(?::\d+)?$/, "");
  const dot = withoutPosition.lastIndexOf(".");
  if (dot <= 0) return "plain";
  return EXTENSION_LANGUAGES[withoutPosition.slice(dot + 1).toLowerCase()] ?? "plain";
}

function tokenize(escaped: string, spec: LanguageSpec): Token[] {
  if (spec.plain) return escaped === "" ? [] : [{ kind: null, text: escaped }];

  const tokens: Token[] = [];
  let plain = "";

  function flush(): void {
    if (plain === "") return;
    tokens.push({ kind: null, text: plain });
    plain = "";
  }

  function emit(kind: TokenKind, text: string): void {
    if (text === "") return;
    flush();
    const last = tokens[tokens.length - 1];
    // A run like `===` or `=>` is one operator to the eye. Merging it into one
    // span renders identically and keeps the embedded HTML appreciably smaller.
    // The flush above means anything in between, even a space, prevents a merge.
    if (last !== undefined && last.kind === "punctuation" && kind === "punctuation") {
      last.text += text;
      return;
    }
    tokens.push({ kind, text });
  }

  /**
   * An excerpt routinely cuts a line in half, so a quoted string that never
   * closes stops at the newline. Running it to the end of the block instead
   * would paint every remaining line as string content and hide the code the
   * reader came for.
   */
  function scanQuoted(start: number, quote: string, multiline: boolean): number {
    let index = start + quote.length;
    while (index < escaped.length) {
      const character = escaped.charAt(index);
      if (character === "\\") {
        index += 2;
        continue;
      }
      if (escaped.startsWith(quote, index)) {
        index += quote.length;
        break;
      }
      if (character === "\n" && !multiline) break;
      index += 1;
    }
    const end = Math.min(index, escaped.length);
    emit("string", escaped.slice(start, end));
    return end;
  }

  /**
   * Backtick strings, including the interpolation inside them. Interpolation is
   * worth the extra handling: in a real finding the interpolated expression is
   * usually the vulnerability, and colouring it differently is what makes the
   * reader's eye land on it.
   */
  function scanTemplate(start: number, depth: number): number {
    let index = start + 1;
    let literalStart = start;
    while (index < escaped.length) {
      const character = escaped.charAt(index);
      if (character === "\\" && !spec.rawBacktick) {
        index += 2;
        continue;
      }
      if (character === "`") {
        index += 1;
        emit("string", escaped.slice(literalStart, index));
        return index;
      }
      if (
        spec.templates &&
        character === "$" &&
        escaped.charAt(index + 1) === "{" &&
        depth < TEMPLATE_DEPTH_LIMIT
      ) {
        emit("string", escaped.slice(literalStart, index));
        emit("punctuation", "${");
        index = run(index + 2, depth + 1);
        if (escaped.charAt(index) === "}") {
          emit("punctuation", "}");
          index += 1;
        }
        literalStart = index;
        continue;
      }
      index += 1;
    }
    emit("string", escaped.slice(literalStart));
    return escaped.length;
  }

  /**
   * Scans to the end of the input, or — inside an interpolation — to the `}`
   * that closes it. Every branch advances the index, so this cannot spin.
   */
  function run(from: number, depth: number): number {
    let index = from;
    let braces = 0;

    while (index < escaped.length) {
      const character = escaped.charAt(index);

      if (depth > 0 && (character === "{" || character === "}")) {
        if (character === "}" && braces === 0) {
          flush();
          return index;
        }
        braces += character === "{" ? 1 : -1;
        emit("punctuation", character);
        index += 1;
        continue;
      }

      const block = spec.blockComment;
      if (block && escaped.startsWith(block[0], index)) {
        const close = escaped.indexOf(block[1], index + block[0].length);
        const end = close === -1 ? escaped.length : close + block[1].length;
        emit("comment", escaped.slice(index, end));
        index = end;
        continue;
      }

      const lineMarker = spec.lineComments.find((marker) => escaped.startsWith(marker, index));
      if (lineMarker !== undefined) {
        const newline = escaped.indexOf("\n", index);
        const end = newline === -1 ? escaped.length : newline;
        emit("comment", escaped.slice(index, end));
        index = end;
        continue;
      }

      // Entities are consumed whole, before any rule that could split them.
      const entity = entityAt(escaped, index);
      if (entity !== null) {
        emit("punctuation", entity);
        index += entity.length;
        continue;
      }

      if (spec.tripleQuotes) {
        const triple = ['"""', "'''"].find((quote) => escaped.startsWith(quote, index));
        if (triple !== undefined) {
          index = scanQuoted(index, triple, true);
          continue;
        }
      }
      if (character === "`" && (spec.templates || spec.rawBacktick)) {
        index = scanTemplate(index, depth);
        continue;
      }
      if (spec.quotes.includes(character)) {
        index = scanQuoted(index, character, false);
        continue;
      }

      NUMBER.lastIndex = index;
      const number = NUMBER.exec(escaped);
      if (number !== null) {
        emit("number", number[0]);
        index += number[0].length;
        continue;
      }

      IDENTIFIER.lastIndex = index;
      const identifier = IDENTIFIER.exec(escaped);
      if (identifier !== null) {
        const word = identifier[0];
        const lookup = spec.caseInsensitiveKeywords ? word.toLowerCase() : word;
        if (spec.keywords.has(lookup)) emit("keyword", word);
        else if (isCallSite(escaped, index + word.length)) emit("function", word);
        else plain += word;
        index += word.length;
        continue;
      }

      if (PUNCTUATION.has(character)) {
        emit("punctuation", character);
        index += 1;
        continue;
      }

      plain += character;
      index += 1;
    }

    flush();
    return index;
  }

  run(0, 0);
  flush();
  return tokens;
}

/**
 * Splits the token stream into one HTML string per line. Tokens legitimately
 * span lines — a block comment, a multi-line template — so the wrapper is closed
 * at the newline and reopened after it, which is what lets each line become its
 * own row without a span leaking across the gutter.
 */
function tokensToLines(tokens: readonly Token[]): string[] {
  const lines: string[] = [];
  let current = "";
  for (const token of tokens) {
    const pieces = token.text.split("\n");
    for (let index = 0; index < pieces.length; index += 1) {
      if (index > 0) {
        lines.push(current);
        current = "";
      }
      const piece = pieces[index] ?? "";
      if (piece === "") continue;
      current += token.kind === null ? piece : `<span class="${CLASS_FOR[token.kind]}">${piece}</span>`;
    }
  }
  lines.push(current);
  return lines;
}

/**
 * Wraps the recognisable parts of `source` in span elements. The text itself is
 * never altered: strip the spans back out and you have the escaped source,
 * character for character.
 */
export function highlight(source: string, language?: string): string {
  const spec = LANGUAGES[normalizeLanguage(language)] ?? PLAIN;
  return tokensToLines(tokenize(escapeCode(normalizeSource(source)), spec)).join("\n");
}

export interface RenderCodeOptions {
  /** Absolute file line number of the first line of `source`. Defaults to 1. */
  startLine?: number;
  /**
   * Inclusive line range to emphasise, in the same absolute numbering as
   * `startLine`, so a finding's own lineStart/lineEnd can be passed straight
   * through. A range that falls outside the excerpt emphasises nothing.
   */
  highlight?: [number, number];
  /** Language id or alias. Derived from `filePath` when omitted. */
  language?: string;
  filePath?: string;
}

/**
 * One code block: a labelled frame, a non-selectable line-number gutter, and the
 * flagged lines marked by an accent bar, a tint, and a glyph — three signals, so
 * the emphasis survives a colour-blind reader, a greyscale printer, and a
 * screen reader alike.
 */
export function renderCode(source: string, options: RenderCodeOptions = {}): string {
  const normalized = normalizeSource(source);
  // An empty frame would claim there was code to show.
  if (normalized.trim() === "") return "";

  const language = normalizeLanguage(options.language ?? (options.filePath ? languageFor(options.filePath) : "plain"));
  // A trailing newline ends the last line, it does not add an empty one.
  const body = normalized.endsWith("\n") ? normalized.slice(0, -1) : normalized;
  const lines = tokensToLines(tokenize(escapeCode(body), LANGUAGES[language] ?? PLAIN));

  const requested = options.startLine;
  const startLine =
    typeof requested === "number" && Number.isFinite(requested) && requested >= 1 ? Math.floor(requested) : 1;

  const range = options.highlight;
  const hasRange = Array.isArray(range) && Number.isFinite(range[0]) && Number.isFinite(range[1]);
  const flagFrom = hasRange ? Math.min(range[0], range[1]) : 0;
  const flagTo = hasRange ? Math.max(range[0], range[1]) : -1;

  const rows = lines
    .map((line, index) => {
      const number = startLine + index;
      const flagged = hasRange && number >= flagFrom && number <= flagTo;
      // The marker sits inside the gutter, which is excluded from a selection,
      // so a screen reader announces it and a paste never picks it up.
      const marker = flagged ? `<span class="codeline-flag">Flagged line ${number}. </span>` : "";
      return (
        `<span class="codeline"${flagged ? ` data-flag="true"` : ""}>` +
        `<span class="codeline-n" data-line="${number}">${marker}</span>` +
        `<span class="codeline-src">${line}</span>` +
        `</span>`
      );
    })
    .join("");

  const path = options.filePath ? escapeAttribute(options.filePath) : "";
  const label = LANGUAGE_LABELS[language] ?? "";
  const lineRange =
    options.startLine === undefined
      ? ""
      : lines.length > 1
        ? `lines ${startLine}-${startLine + lines.length - 1}`
        : `line ${startLine}`;
  const meta = [lineRange, label].filter(Boolean).join("  ·  ");
  const caption =
    path || meta
      ? `<figcaption class="codeblock-head">` +
        `<span class="codeblock-path">${path}</span>` +
        (meta ? `<span class="codeblock-meta">${escapeAttribute(meta)}</span>` : "") +
        `</figcaption>`
      : "";

  // A scrollable region has to be focusable, or a keyboard-only reader cannot
  // reach the part of the line that runs past the right edge.
  const region = `Code excerpt${options.filePath ? ` from ${escapeAttribute(options.filePath)}` : ""}`;

  return (
    `<figure class="codeblock" data-lang="${escapeAttribute(language)}">` +
    caption +
    `<div class="codeblock-scroll" tabindex="0" role="group" aria-label="${region}">` +
    `<pre class="codeblock-pre"><code class="codeblock-code">${rows}</code></pre>` +
    `</div></figure>`
  );
}

/**
 * The stylesheet for the above, concatenated into the report's own. Every colour
 * resolves to a variable the report already defines, so the block follows the
 * report's theme instead of introducing a second palette; the literal fallbacks
 * only matter if these styles are ever used outside the report shell.
 */
export const CODE_STYLES = `
:root{
  /* Monochrome on purpose. Syntax is told apart by weight, style, and tone, so
     the only colour on the page stays the green that means "verified". */
  --codeBg:var(--canvas,#0A0A0A);
  --codeHeadBg:var(--surface,#111111);
  --codeText:var(--text,#F5F5F5);
  --codeGutter:var(--faint,#8A8A8A);
  --codeComment:var(--faint,#8A8A8A);
  --codeString:var(--muted,#B5B5B5);
  --codeNumber:var(--text,#F5F5F5);
  --codeKeyword:var(--text,#F5F5F5);
  --codeFunction:var(--text,#F5F5F5);
  --codePunct:var(--muted,#B5B5B5);
  --codeFlag:var(--text,#F5F5F5);
  /* A translucent tint so the sticky gutter can layer the same band over its
     own backdrop and the two read as one. */
  --codeFlagBg:var(--flagBg,rgba(255,255,255,.07));
  --codeMono:var(--mono, ui-monospace, SFMono-Regular, "SF Mono", Menlo, Consolas, "Liberation Mono", monospace);
}
.codeblock{margin:10px 0 0;border:1px solid var(--border,#262626);border-radius:8px;background:var(--codeBg);overflow:hidden}
.codeblock-head{display:flex;flex-wrap:wrap;gap:2px 14px;justify-content:space-between;align-items:baseline;padding:8px 12px;background:var(--codeHeadBg);border-bottom:1px solid var(--border,#262626);font:400 11px/1.5 var(--codeMono);color:var(--codePunct)}
.codeblock-path{color:var(--codeText);word-break:break-all}
.codeblock-meta{white-space:nowrap}
.codeblock-scroll{overflow-x:auto;overflow-y:hidden}
.codeblock-scroll:focus-visible{outline:2px solid var(--focus,#F5F5F5);outline-offset:-2px}
/* Neutralises the report's generic pre rule; this block draws its own frame. */
.codeblock-pre{margin:0;padding:0;border:0;background:none;border-radius:0;overflow:visible}
.codeblock-code{display:block;font:400 12px/1.65 var(--codeMono);color:var(--codeText)}
.codeline{display:flex;align-items:flex-start;width:max-content;min-width:100%;min-height:1.65em}
/* The gutter is never part of a selection, so a copied block is code only. */
.codeline-n{position:sticky;left:0;z-index:1;flex:0 0 auto;display:inline-flex;align-items:baseline;justify-content:flex-end;gap:6px;min-width:52px;padding:0 10px 0 7px;border-left:3px solid transparent;background:var(--codeBg);color:var(--codeGutter);-webkit-user-select:none;user-select:none}
.codeline-n::before{content:attr(data-line)}
.codeline-n::after{content:"";width:9px;text-align:center;color:var(--codeFlag)}
.codeline-src{flex:1 0 auto;padding:0 16px 0 0;white-space:pre}
.codeline[data-flag="true"]{background:var(--codeFlagBg)}
.codeline[data-flag="true"] .codeline-n{border-left-color:var(--codeFlag);color:var(--codeText);background:linear-gradient(var(--codeFlagBg),var(--codeFlagBg)),var(--codeBg)}
.codeline[data-flag="true"] .codeline-n::after{content:"▸"}
.codeline-flag{position:absolute;width:1px;height:1px;margin:-1px;padding:0;overflow:hidden;clip-path:inset(50%);white-space:nowrap;border:0}
.tok-comment{color:var(--codeComment);font-style:italic}
.tok-string{color:var(--codeString)}
.tok-number{color:var(--codeNumber)}
.tok-keyword{color:var(--codeKeyword);font-weight:700}
.tok-function{color:var(--codeFunction);text-decoration:underline;text-decoration-color:var(--borderStrong,#3A3A3A);text-underline-offset:3px}
.tok-punct{color:var(--codePunct)}
@media (max-width:720px){
  .codeblock-code{font-size:11px}
  .codeline-n{min-width:42px;padding:0 8px 0 5px}
}
@media (prefers-reduced-motion: reduce){
  /* The block ships no motion of its own; this keeps an inherited transition
     from the surrounding page out of it as well. */
  .codeblock,.codeblock *{animation:none;transition:none;scroll-behavior:auto}
}
@media print{
  /* Nothing scrolls on paper, so the frame goes black-on-white and long lines
     wrap instead of being cut off at the right edge. */
  .codeblock{background:#fff;border-color:#cfcfcf;break-inside:avoid}
  .codeblock-head{background:#fff;border-bottom-color:#cfcfcf;color:#3d3d3d}
  .codeblock-path{color:#101010}
  .codeblock-scroll{overflow:visible}
  .codeblock-code{color:#101010}
  .codeline{width:auto}
  /* flex-shrink and min-width both have to give, or the row keeps its
     max-content width and pre-wrap never gets the chance to wrap. */
  .codeline-src{flex:1 1 auto;min-width:0;white-space:pre-wrap;overflow-wrap:anywhere}
  .codeline-n{position:static;background:#fff;color:#5b5b5b;border-right:1px solid #e4e4e4}
  .codeline[data-flag="true"]{background:#efefef}
  .codeline[data-flag="true"] .codeline-n{background:#efefef;border-left-color:#101010;color:#101010}
  .tok-comment{color:#5b5b5b}
  .tok-string{color:#3d3d3d}
  .tok-number,.tok-keyword,.tok-function{color:#101010}
  .tok-punct{color:#3d3d3d}
}
`;
