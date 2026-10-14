import type { Expr, Span } from "../syntax/ast.js";
import { constString, dotted, isTrue, keyword } from "../syntax/ast.js";
import type { PyModule } from "../project/modules.js";
import { isTaintedFor, type SinkClass, type Taint, type Value } from "./values.js";

/**
 * Where caller-controlled data must not arrive.
 *
 * Each sink is identified by the fully qualified name its module imports it
 * under (`subprocess.run`, `flask.render_template_string`), or for methods by
 * the method name *and* evidence about the receiver — a `.get()` on an `httpx`
 * client is a request, a `.get()` on a dictionary is not. A sink fires only when
 * the argument that matters is tainted for the sink's own class, which is what
 * keeps `subprocess.run([...], shell=False)` and `cursor.execute(sql, params)`
 * quiet.
 */

export interface SinkHit {
  sink: SinkClass;
  module: PyModule;
  span: Span;
  taint: Taint;
  /** What was called, as the report should name it. */
  sinkName: string;
  /** Rule-specific note for the report. */
  detail?: string;
  /**
   * Set when the statement is a parameter passed straight through (`def query(sql):
   * conn.execute(sql)`). Whether it is SQL built from caller data is only known where
   * the helper is called, so the hit is decided there, against the caller's value.
   */
  deferredShape?: "sql";
}

export interface CallSite {
  call: Extract<Expr, { k: "call" }>;
  module: PyModule;
  /** External dotted name, when the callee resolves to an import. */
  qualified: string | null;
  tail: string | null;
  receiver: Value | null;
  args: Value[];
  kwargs: Map<string, Value>;
  /** Whether the callee resolved to a function or class defined in this project. */
  projectCallee: boolean;
  /** Reads a project template file, for `render_template` context checks. */
  templateText: (name: string) => string | null;
  /** What reading `.attr` off a stored record yields: attacker data only if some route stored it. */
  storedField?: (attr: string, line: number) => Value | null;
}

type Report = (hit: Omit<SinkHit, "module" | "span"> & { span?: Span; module?: PyModule }) => void;

export const SQL_SHAPE =
  /\b(select\b[\s\S]*\bfrom|insert\s+into|update\s+[\w."`]+\s+set|delete\s+from|where\b|order\s+by|group\s+by|union\s+(all\s+)?select|values\s*\(|pragma\b|create\s+(table|index)|drop\s+table|alter\s+table|limit\s+\d|having\b)/i;

const SQL_METHODS = new Set(["execute", "executemany", "executescript", "exec_driver_sql", "mogrify", "read_sql", "read_sql_query", "raw"]);

const SHELL_ALWAYS = new Set([
  "os.system",
  "os.popen",
  "subprocess.getoutput",
  "subprocess.getstatusoutput",
  "commands.getoutput",
  "commands.getstatusoutput",
  "asyncio.create_subprocess_shell",
  "asyncio.subprocess.create_subprocess_shell"
]);

const SUBPROCESS = new Set(["subprocess.run", "subprocess.call", "subprocess.check_call", "subprocess.check_output", "subprocess.Popen"]);

/**
 * File-opening functions: which positional argument is the path, and which
 * keyword spells it. The keyword matters: `FileResponse(path, filename=...)`
 * takes the *download name* as `filename`, and reading that instead of the path
 * once hid a traversal behind a correctly basenamed display name.
 */
const FILE_FUNCTIONS: ReadonlyMap<string, { index: number; names: string[] }[]> = new Map([
  ["io.open", [{ index: 0, names: ["file"] }]],
  ["codecs.open", [{ index: 0, names: ["filename"] }]],
  ["aiofiles.open", [{ index: 0, names: ["file"] }]],
  ["os.open", [{ index: 0, names: ["path"] }]],
  ["os.remove", [{ index: 0, names: ["path"] }]],
  ["os.unlink", [{ index: 0, names: ["path"] }]],
  ["os.rmdir", [{ index: 0, names: ["path"] }]],
  ["os.removedirs", [{ index: 0, names: ["name"] }]],
  ["os.listdir", [{ index: 0, names: ["path"] }]],
  ["os.scandir", [{ index: 0, names: ["path"] }]],
  ["os.makedirs", [{ index: 0, names: ["name"] }]],
  ["os.mkdir", [{ index: 0, names: ["path"] }]],
  ["os.rename", [{ index: 0, names: ["src"] }, { index: 1, names: ["dst"] }]],
  ["os.replace", [{ index: 0, names: ["src"] }, { index: 1, names: ["dst"] }]],
  ["shutil.copy", [{ index: 0, names: ["src"] }, { index: 1, names: ["dst"] }]],
  ["shutil.copy2", [{ index: 0, names: ["src"] }, { index: 1, names: ["dst"] }]],
  ["shutil.copyfile", [{ index: 0, names: ["src"] }, { index: 1, names: ["dst"] }]],
  ["shutil.copytree", [{ index: 0, names: ["src"] }, { index: 1, names: ["dst"] }]],
  ["shutil.move", [{ index: 0, names: ["src"] }, { index: 1, names: ["dst"] }]],
  ["shutil.rmtree", [{ index: 0, names: ["path"] }]],
  ["zipfile.ZipFile", [{ index: 0, names: ["file"] }]],
  ["tarfile.open", [{ index: 0, names: ["name"] }]],
  ["flask.send_file", [{ index: 0, names: ["path_or_file", "filename_or_fp"] }]],
  ["flask.helpers.send_file", [{ index: 0, names: ["path_or_file", "filename_or_fp"] }]],
  ["quart.send_file", [{ index: 0, names: ["filename_or_io"] }]],
  ["fastapi.responses.FileResponse", [{ index: 0, names: ["path"] }]],
  ["starlette.responses.FileResponse", [{ index: 0, names: ["path"] }]],
  // send_from_directory joins safely; only the directory argument is a path sink.
  ["flask.send_from_directory", [{ index: 0, names: ["directory"] }]],
  ["flask.helpers.send_from_directory", [{ index: 0, names: ["directory"] }]]
]);

const PATH_METHODS = new Set(["open", "read_text", "read_bytes", "write_text", "write_bytes", "unlink", "rmdir", "mkdir", "touch", "rename", "iterdir", "rglob", "glob"]);

const HTTP_VERBS = new Set(["get", "post", "put", "patch", "delete", "head", "options", "request", "stream", "send"]);
const HTTP_MODULES = /^(requests|httpx|aiohttp|urllib3|niquests|treq)\.(get|post|put|patch|delete|head|options|request|stream)$/;
const URL_OPENERS = new Set(["urllib.request.urlopen", "urllib.request.Request", "urllib.urlopen", "urllib2.urlopen", "six.moves.urllib.request.urlopen"]);

const DESERIALIZERS = new Set([
  "pickle.loads",
  "pickle.load",
  "_pickle.loads",
  "_pickle.load",
  "cPickle.loads",
  "cPickle.load",
  "dill.loads",
  "dill.load",
  "cloudpickle.loads",
  "cloudpickle.load",
  "marshal.loads",
  "marshal.load",
  "jsonpickle.decode",
  "jsonpickle.loads",
  "pandas.read_pickle",
  "joblib.load",
  "shelve.open",
  "yaml.unsafe_load",
  "yaml.unsafe_load_all",
  "yaml.full_load",
  "yaml.full_load_all"
]);

const SAFE_YAML_LOADER = /(Safe|CSafe|Base)Loader$/;

const TEMPLATE_STRING_RENDERERS = /^(flask|quart|flask\.templating)\.render_template_string$/;
const TEMPLATE_CONSTRUCTORS = /^(jinja2\.Template|jinja2\.environment\.Template|mako\.template\.Template|django\.template\.Template)$/;
const REDIRECTS = /^(flask|quart|werkzeug|werkzeug\.utils|flask\.helpers)\.redirect$/;
const REDIRECT_RESPONSES = /^(fastapi|starlette)\.responses\.RedirectResponse$|^fastapi\.RedirectResponse$/;
const MARKUP = /^(markupsafe|flask|jinja2|jinja2\.utils|flask\.helpers)\.Markup$/;
const HTML_RESPONSES = /^(fastapi|starlette)\.responses\.HTMLResponse$|^fastapi\.HTMLResponse$/;
const GENERIC_RESPONSES = /^((fastapi|starlette)\.responses\.Response|fastapi\.Response|flask\.Response|flask\.make_response|werkzeug\.wrappers\.Response|quart\.make_response)$/;

export function argument(site: CallSite, index: number, ...names: string[]): Value | undefined {
  for (const name of names) {
    const value = site.kwargs.get(name);
    if (value) return value;
  }
  return site.args[index];
}

function argumentExpr(site: CallSite, index: number, ...names: string[]): Expr | undefined {
  for (const name of names) {
    const value = keyword(site.call, name);
    if (value) return value;
  }
  return site.call.args[index];
}

export function checkSinks(site: CallSite, report: Report): void {
  if (site.projectCallee) return;
  const q = site.qualified ?? "";
  const tail = site.tail ?? "";

  /* ---- SQL ---- */
  if (/^(sqlalchemy(\.sql)?(\.expression)?|sqlmodel)\.(text|literal_column)$/.test(q) || /^psycopg2?\.sql\.SQL$/.test(q)) {
    const statement = argument(site, 0, "text");
    if (statement && isTaintedFor(statement, "sql")) {
      report({ sink: "sql", taint: statement.taint!, sinkName: `${tail}()`, detail: "text-clause" });
    }
  } else if (SQL_METHODS.has(tail) && !site.receiver?.tags.has("request")) {
    const statement = argument(site, 0, "statement", "sql", "query", "operation");
    const statementExpr = argumentExpr(site, 0, "statement", "sql", "query", "operation");
    const viaClause = statement?.tags.has("text-clause") || (statementExpr?.k === "call" && /(^|\.)(text|SQL)$/.test(dotted(statementExpr.func) ?? ""));
    if (statement && !viaClause && isTaintedFor(statement, "sql") && SQL_SHAPE.test(statement.text)) {
      report({ sink: "sql", taint: statement.taint!, sinkName: `${dotted(site.call.func) ?? tail}()` });
    } else if (statement && !viaClause && isTaintedFor(statement, "sql") && isPassThrough(statement)) {
      report({ sink: "sql", taint: statement.taint!, sinkName: `${dotted(site.call.func) ?? tail}()`, deferredShape: "sql" });
    }
  }

  /* ---- command ---- */
  if (SHELL_ALWAYS.has(q)) {
    const command = argument(site, 0, "cmd", "command");
    if (command && isTaintedFor(command, "command")) report({ sink: "command", taint: command.taint!, sinkName: `${q}()` });
  } else if (SUBPROCESS.has(q) || /^asyncio\.create_subprocess_exec$/.test(q)) {
    const shell = keyword(site.call, "shell");
    const commandExpr = argumentExpr(site, 0, "args");
    const command = argument(site, 0, "args");
    if (isTrue(shell) && command && isTaintedFor(command, "command") && commandExpr?.k !== "list") {
      report({ sink: "command", taint: command.taint!, sinkName: `${q}(shell=True)` });
    } else if (commandExpr?.k === "list" && commandExpr.elts.length >= 3) {
      const program = constString(commandExpr.elts[0]) ?? "";
      const flag = constString(commandExpr.elts[1]) ?? "";
      if (/(^|\/)(sh|bash|zsh|dash|cmd(\.exe)?|powershell)$/.test(program) && /^(-c|\/c|-Command)$/.test(flag)) {
        const script = site.args[0];
        if (script && isTaintedFor(script, "command")) {
          report({ sink: "command", taint: script.taint!, sinkName: `${q}([${program}, ${flag}, …])` });
        }
      }
    }
  }

  /* ---- path ---- */
  const isBuiltinOpen = site.call.func.k === "name" && site.call.func.id === "open" && site.qualified === null;
  const fileArguments = isBuiltinOpen ? [{ index: 0, names: ["file"] }] : FILE_FUNCTIONS.get(q);
  if (fileArguments) {
    for (const spec of fileArguments) {
      const target = argument(site, spec.index, ...spec.names);
      if (target && isTaintedFor(target, "path")) {
        report({ sink: "path", taint: target.taint!, sinkName: `${isBuiltinOpen ? "open" : q}()` });
        break;
      }
    }
  } else if (PATH_METHODS.has(tail) && site.receiver?.tags.has("path-object") && isTaintedFor(site.receiver, "path")) {
    report({ sink: "path", taint: site.receiver.taint!, sinkName: `Path.${tail}()` });
  }

  /* ---- outbound requests ---- */
  if (HTTP_MODULES.test(q) || URL_OPENERS.has(q)) {
    const url = /\.request$/.test(q) && !URL_OPENERS.has(q) ? argument(site, 1, "url") : argument(site, 0, "url");
    if (url && isTaintedFor(url, "ssrf")) report({ sink: "ssrf", taint: url.taint!, sinkName: `${q}()` });
  } else if (HTTP_VERBS.has(tail) && site.receiver?.tags.has("http-client")) {
    const url = tail === "request" || tail === "stream" ? argument(site, 1, "url") : argument(site, 0, "url");
    if (url && isTaintedFor(url, "ssrf")) report({ sink: "ssrf", taint: url.taint!, sinkName: `client.${tail}()` });
  }

  /* ---- templates ---- */
  if (TEMPLATE_STRING_RENDERERS.test(q)) {
    const template = argument(site, 0, "source");
    if (template && isTaintedFor(template, "template")) {
      report({ sink: "template", taint: template.taint!, sinkName: "render_template_string()" });
    } else if (template && !template.taint) {
      contextThroughUnescapedMarkup(site, keywordContext(site), template.text, report, "render_template_string()");
    }
  } else if (TEMPLATE_CONSTRUCTORS.test(q)) {
    const template = argument(site, 0, "source");
    if (template && isTaintedFor(template, "template")) report({ sink: "template", taint: template.taint!, sinkName: `${q}()` });
  } else if (tail === "from_string" && !site.receiver?.tags.has("jinja-sandbox") && (site.receiver?.tags.has("jinja-env") || /env|jinja/i.test(dotted(site.call.func) ?? ""))) {
    const template = argument(site, 0, "source");
    if (template && isTaintedFor(template, "template")) report({ sink: "template", taint: template.taint!, sinkName: "Environment.from_string()" });
  } else if (/^(flask|quart)\.render_template$/.test(q)) {
    const name = constString(site.call.args[0]);
    const text = name ? site.templateText(name) : null;
    if (text) contextThroughUnescapedMarkup(site, keywordContext(site), text, report, `render_template("${name}")`);
  } else if (/^(render|render_async|stream|generate)$/.test(tail) && site.receiver?.template) {
    // `PAGE = env.from_string("…{{ note.body_html | safe }}…")`, `env.get_template(name)`.
    const template = site.receiver.template;
    contextThroughUnescapedMarkup(site, keywordContext(site), template.text, report, `${dotted(site.call.func) ?? tail}()`, template);
  } else if (tail === "TemplateResponse" && site.receiver?.tags.has("jinja-templates")) {
    // `templates.TemplateResponse("note.html", {"request": request, "note": note})`, and
    // the newer `TemplateResponse(request, "note.html", context)`.
    const nameIndex = constString(site.call.args[0]) !== null ? 0 : 1;
    const name = constString(keyword(site.call, "name") ?? site.call.args[nameIndex]);
    const text = name ? site.templateText(name) : null;
    const contextExpr = keyword(site.call, "context") ?? site.call.args[nameIndex + 1];
    const contextValue = site.kwargs.get("context") ?? site.args[nameIndex + 1];
    if (text && contextExpr?.k === "dict" && contextValue?.entryValues) {
      contextThroughUnescapedMarkup(site, contextValue.entryValues, text, report, `TemplateResponse("${name}")`);
    }
  }

  /* ---- deserialization ---- */
  if (DESERIALIZERS.has(q)) {
    const data = argument(site, 0, "data", "file", "s");
    if (data && isTaintedFor(data, "deserialization")) report({ sink: "deserialization", taint: data.taint!, sinkName: `${q}()` });
  } else if (q === "yaml.load" || q === "yaml.load_all") {
    const loader = keyword(site.call, "Loader") ?? site.call.args[1];
    const loaderName = loader ? dotted(loader) ?? "" : "";
    const data = argument(site, 0, "stream");
    if (!SAFE_YAML_LOADER.test(loaderName) && data && isTaintedFor(data, "deserialization")) {
      report({
        sink: "deserialization",
        taint: data.taint!,
        sinkName: `${q}(${loaderName ? `Loader=${loaderName}` : "no Loader"})`
      });
    }
  } else if (/^numpy\.load$/.test(q) && isTrue(keyword(site.call, "allow_pickle"))) {
    const data = argument(site, 0, "file");
    if (data && isTaintedFor(data, "deserialization")) report({ sink: "deserialization", taint: data.taint!, sinkName: "numpy.load(allow_pickle=True)" });
  }

  /* ---- redirects ---- */
  if (REDIRECTS.test(q) || REDIRECT_RESPONSES.test(q)) {
    const location = argument(site, 0, "location", "url");
    if (location && isTaintedFor(location, "redirect")) report({ sink: "redirect", taint: location.taint!, sinkName: `${tail}()` });
  }

  /* ---- markup ---- */
  if (MARKUP.test(q)) {
    const markup = argument(site, 0, "base", "object");
    if (markup && isTaintedFor(markup, "xss")) report({ sink: "xss", taint: markup.taint!, sinkName: "Markup()" });
  } else if (HTML_RESPONSES.test(q)) {
    const content = argument(site, 0, "content");
    if (content && isTaintedFor(content, "xss")) report({ sink: "xss", taint: content.taint!, sinkName: "HTMLResponse()" });
  } else if (GENERIC_RESPONSES.test(q)) {
    const content = argument(site, 0, "content", "response");
    const mediaType = constString(keyword(site.call, "media_type") ?? keyword(site.call, "mimetype") ?? keyword(site.call, "content_type")) ?? "";
    const isFlaskDefault = /make_response$|^flask\.Response$/.test(q) && mediaType === "";
    const html = /html/i.test(mediaType) || (isFlaskDefault && content !== undefined && /<[a-z!/]/i.test(content.text));
    if (html && content && isTaintedFor(content, "xss")) report({ sink: "xss", taint: content.taint!, sinkName: `${tail}()` });
  }
}

function keywordContext(site: CallSite): ReadonlyMap<string, Value> {
  return site.kwargs;
}

/**
 * A constant template that marks a context variable `|safe` (or turns
 * autoescaping off) hands that variable's markup straight to the browser.
 *
 * The marked expression may be an attribute of a context variable (`note.body_html`),
 * or of a loop variable over one (`{% for c in comments %}{{ c.body | safe }}`). Such an
 * attribute is the variable's own taint when the variable is attacker data, and
 * otherwise a stored field, which is attacker data only if some route stored it.
 *
 * A template written in the code is reported at the line that marks the value safe,
 * which is the line to change; a template file, at the call that renders it.
 */
function contextThroughUnescapedMarkup(
  site: CallSite,
  context: ReadonlyMap<string, Value>,
  template: string,
  report: Report,
  sinkName: string,
  inline?: { text: string; module: unknown; line: number | null }
): void {
  const autoescapeOff = /\{%-?\s*autoescape\s+(false|False)\s*-?%\}/.test(template);
  const aliases = new Map<string, string>();
  for (const loop of template.matchAll(/\{%-?\s*for\s+([\w\s,()]+?)\s+in\s+(\w+)/g)) {
    for (const name of loop[1]!.split(/[\s,()]+/).filter(Boolean)) aliases.set(name, loop[2]!);
  }
  const marked = autoescapeOff ? /\{\{-?\s*([A-Za-z_][\w.]*)/g : /\{\{-?\s*([A-Za-z_][\w.]*)\s*\|\s*safe\b/g;
  for (const match of template.matchAll(marked)) {
    const [root, ...attrs] = match[1]!.split(".");
    const variable = context.has(root!) ? root! : aliases.get(root!);
    const value = variable ? context.get(variable) : undefined;
    if (!value) continue;
    const line = inline?.line != null ? inline.line + (template.slice(0, match.index).match(/\n/g)?.length ?? 0) : site.call.span.line;
    const attr = attrs.at(-1);
    const reached = isTaintedFor(value, "xss") ? value : attr && site.storedField ? site.storedField(attr, line) : null;
    if (!reached || !isTaintedFor(reached, "xss")) continue;
    report({
      sink: "xss",
      taint: reached.taint!,
      sinkName,
      detail: `${match[1]} is rendered without escaping`,
      ...(inline?.line != null ? { span: { line, endLine: line, from: site.call.span.from, to: site.call.span.to }, module: inline.module as PyModule } : {})
    });
    return;
  }
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

export const SQL_TEXT_SHAPE = SQL_SHAPE;

/** A value that is only a function's parameter, with no text of its own around it. */
function isPassThrough(value: Value): boolean {
  return value.text === "" && Boolean(value.taint?.origins.every((origin) => origin.kind === "param"));
}
