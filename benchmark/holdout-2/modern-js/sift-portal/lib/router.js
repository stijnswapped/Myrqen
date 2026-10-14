/**
 * The smallest router that does what the portal needs: literal segments, a
 * `:name` capture, and nothing else. Route modules are loaded once at boot and
 * each exports `method`, `path` and `handler`.
 */

function compile(pattern) {
  const names = [];
  const source = pattern
    .split("/")
    .map((segment) => {
      if (!segment.startsWith(":")) return segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      names.push(segment.slice(1));
      return "([^/]+)";
    })
    .join("/");
  return { names, regex: new RegExp(`^${source}$`) };
}

export function createRouter(modules) {
  const routes = modules.map((module) => ({
    method: module.method,
    handler: module.handler,
    ...compile(module.path),
  }));

  return async function dispatch(request) {
    const url = new URL(request.url);

    for (const route of routes) {
      if (route.method !== request.method) continue;
      const match = route.regex.exec(url.pathname);
      if (!match) continue;

      const params = Object.fromEntries(route.names.map((name, index) => [name, decodeURIComponent(match[index + 1])]));
      return route.handler({
        request,
        params,
        query: url.searchParams,
        html: (markup, status = 200) =>
          new Response(markup, { status, headers: { "content-type": "text/html; charset=utf-8" } }),
      });
    }

    return new Response("Not found", { status: 404 });
  };
}
