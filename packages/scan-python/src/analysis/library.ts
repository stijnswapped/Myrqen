import type { SinkClass, SourceKind } from "./values.js";

/**
 * What the interpreter knows about the Python standard library and the common
 * web stack: where request data enters, which calls clean it and for which
 * sinks, which carry it through, and which construct objects whose methods are
 * themselves sinks. Kept apart from the interpreter so extending the catalogue
 * never means reading the evaluator.
 */

export const REQUEST_SOURCE_ATTRS: Record<string, SourceKind> = {
  args: "query",
  query_params: "query",
  values: "query",
  query_string: "query",
  form: "form",
  json: "body",
  data: "body",
  stream: "body",
  files: "file",
  headers: "header",
  cookies: "cookie",
  view_args: "path",
  path_params: "path",
  path: "path",
  full_path: "path",
  url: "path",
  base_url: "path",
  url_root: "path",
  host: "header",
  host_url: "header",
  referrer: "header",
  user_agent: "header",
  remote_user: "header",
  authorization: "header"
};

export const REQUEST_SOURCE_METHODS: Record<string, SourceKind> = {
  get_json: "body",
  get_data: "body",
  json: "body",
  form: "form",
  body: "body",
  stream: "body"
};

/** Methods that answer a question about a value rather than returning it. */
export const PREDICATE_METHODS = new Set([
  "startswith",
  "endswith",
  "isdigit",
  "isalnum",
  "isalpha",
  "isdecimal",
  "isnumeric",
  "isidentifier",
  "isspace",
  "islower",
  "isupper",
  "count",
  "find",
  "rfind",
  "index",
  "rindex",
  "exists",
  "is_file",
  "is_dir",
  "is_relative_to",
  "__len__",
  "__contains__",
  "hexdigest",
  "digest"
]);

export const MUTATORS = new Set(["append", "extend", "add", "update", "insert", "appendleft", "setdefault"]);

/** Functions whose result carries nothing of their input that an attacker can steer. */
export const CLEAN_ALL_FUNCTIONS = new Set([
  "int",
  "float",
  "bool",
  "len",
  "abs",
  "round",
  "hash",
  "ord",
  "id",
  "isinstance",
  "hasattr",
  "callable",
  "uuid.UUID",
  "UUID",
  "decimal.Decimal",
  "Decimal",
  "datetime.datetime.fromisoformat",
  "datetime.date.fromisoformat",
  "datetime.fromisoformat",
  "date.fromisoformat",
  "hashlib.sha256",
  "hashlib.sha1",
  "hashlib.md5",
  "hashlib.sha512",
  "hmac.new",
  "hmac.compare_digest",
  "secrets.compare_digest",
  "secrets.token_hex",
  "secrets.token_urlsafe",
  "url_for",
  "flask.url_for",
  "quart.url_for"
]);

export const SANITIZERS: ReadonlyMap<string, readonly SinkClass[]> = new Map<string, readonly SinkClass[]>([
  ["os.path.basename", ["path"]],
  ["posixpath.basename", ["path"]],
  ["ntpath.basename", ["path"]],
  ["werkzeug.utils.secure_filename", ["path", "command", "sql", "xss", "template", "redirect", "ssrf"]],
  ["werkzeug.secure_filename", ["path", "command", "sql", "xss", "template", "redirect", "ssrf"]],
  ["werkzeug.security.safe_join", ["path"]],
  ["werkzeug.utils.safe_join", ["path"]],
  ["flask.safe_join", ["path"]],
  ["flask.helpers.safe_join", ["path"]],
  ["shlex.quote", ["command"]],
  ["pipes.quote", ["command"]],
  ["shlex.join", ["command"]],
  ["markupsafe.escape", ["xss"]],
  ["flask.escape", ["xss"]],
  ["jinja2.escape", ["xss"]],
  ["html.escape", ["xss"]],
  ["cgi.escape", ["xss"]],
  ["bleach.clean", ["xss"]],
  ["nh3.clean", ["xss"]],
  ["psycopg2.sql.Identifier", ["sql"]],
  ["psycopg.sql.Identifier", ["sql"]],
  ["psycopg2.sql.Literal", ["sql"]],
  ["psycopg.sql.Literal", ["sql"]],
  ["sqlalchemy.bindparam", ["sql"]]
]);

/** Library functions that return something built from their arguments. */
export const PROPAGATORS = new Set([
  "str",
  "repr",
  "format",
  "bytes",
  "list",
  "tuple",
  "set",
  "dict",
  "sorted",
  "reversed",
  "min",
  "max",
  "next",
  "iter",
  "enumerate",
  "zip",
  "map",
  "filter",
  "os.path.join",
  "os.path.normpath",
  "os.path.expanduser",
  "os.path.splitext",
  "os.path.dirname",
  "os.fspath",
  "posixpath.join",
  "urllib.parse.urljoin",
  "urllib.parse.unquote",
  "urllib.parse.unquote_plus",
  "urllib.parse.quote",
  "urllib.parse.quote_plus",
  "urllib.parse.urlencode",
  "urllib.parse.urlunparse",
  "urllib.parse.parse_qs",
  "urllib.parse.parse_qsl",
  "base64.b64decode",
  "base64.urlsafe_b64decode",
  "base64.b64encode",
  "base64.urlsafe_b64encode",
  "base64.b32decode",
  "base64.b85decode",
  "binascii.unhexlify",
  "binascii.a2b_base64",
  "bytes.fromhex",
  "codecs.decode",
  "zlib.decompress",
  "gzip.decompress",
  "lzma.decompress",
  "bz2.decompress",
  "json.loads",
  "json.dumps",
  "json.load",
  "orjson.loads",
  "ujson.loads",
  "re.sub",
  // Markdown renderers pass raw HTML in the source through to their output.
  "markdown.markdown",
  "markdown2.markdown",
  "re.escape",
  "html.unescape",
  "textwrap.dedent",
  "textwrap.indent",
  "io.BytesIO",
  "io.StringIO",
  "copy.copy",
  "copy.deepcopy",
  "typing.cast",
  "cast"
]);

export const PATH_CONSTRUCTORS = /^(pathlib\.)?(Path|PurePath|PosixPath|PurePosixPath|WindowsPath|anyio\.Path|aiopath\.AsyncPath)$/;
export const RESOLVERS = new Set(["os.path.realpath", "os.path.abspath", "os.path.normpath", "posixpath.realpath", "posixpath.abspath", "posixpath.normpath"]);
export const URL_PARSERS = new Set(["urllib.parse.urlparse", "urllib.parse.urlsplit", "urlparse.urlparse", "furl.furl", "yarl.URL", "httpx.URL"]);
export const HTTP_CLIENTS = /^(httpx\.(Client|AsyncClient)|requests\.(Session|session)|aiohttp\.ClientSession|urllib3\.PoolManager|niquests\.(Session|AsyncSession))$/;
export const JINJA_ENVIRONMENTS = /^(jinja2\.Environment|jinja2\.environment\.Environment)$/;
/** A sandboxed environment is the documented way to render user-authored templates. */
export const JINJA_SANDBOXES = /^jinja2\.sandbox\.(Immutable)?SandboxedEnvironment$/;
export const SIGNERS = /^itsdangerous\.\w*(Serializer|Signer)$/;

/** Name resolution: what comes back is the address a request to that name would reach. */
export const ADDRESS_RESOLVERS = new Set(["socket.gethostbyname", "socket.gethostbyname_ex", "socket.getaddrinfo"]);
/** Address parsers: they keep a resolved address resolved, and a bare name stays a name. */
export const ADDRESS_PARSERS = new Set(["ipaddress.ip_address", "ipaddress.ip_network", "ipaddress.IPv4Address", "ipaddress.IPv6Address"]);
