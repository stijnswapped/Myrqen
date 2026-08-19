/**
 * The simulated host agent.
 *
 * The previous harness detected vulnerabilities itself, from regular expressions
 * written against the fixtures' own source. That measured the harness, not the
 * product: renaming a route in a fixture would have zeroed recall, and nothing a
 * user installs contained any of that logic.
 *
 * This module does what a host agent actually does, and nothing else. It reads
 * the candidates the CLI's own static pass recorded, then exercises the running
 * application to settle each one: verified when the behaviour reproduces, refuted
 * when it does not, left alone when the probe could not be run safely. Every
 * probe is derived from the candidate's own route and category — never from a
 * fixture's file names or identifiers — so a rule that only works on the
 * benchmark cannot pass here either.
 */
import { setTimeout as delay } from "node:timers/promises";

const UA = { "user-agent": "myrqen-benchmark/2.0" };

/** A markup probe whose reflection is unambiguous but which executes nothing. */
const XSS_PROBE = "<myrqen-probe-9f31>";
/**
 * Traversal targets, ordered by how universally they exist. A probe that only
 * tries one path reports "contained" on any host where that file is absent,
 * which is how a real traversal gets refuted by accident.
 */
const TRAVERSAL_TARGETS = [
  "../../../../etc/hosts",
  "../../../../../../etc/passwd",
  "..%2f..%2f..%2f..%2fetc%2fhosts",
  "....//....//....//etc/hosts"
];
/** A predicate terminator that would widen an interpreted query. */
const PREDICATE_PROBE = '") || true || ("';

async function request(url, options = {}) {
  const response = await fetch(url, {
    redirect: "manual",
    ...options,
    headers: { ...UA, ...(options.headers ?? {}) }
  });
  const text = await response.text();
  let body = null;
  try {
    body = JSON.parse(text);
  } catch {
    body = null;
  }
  return { status: response.status, text, body, headers: response.headers };
}

async function login(baseUrl, identity) {
  const response = await request(`${baseUrl}/api/login`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ email: identity.email, password: identity.password })
  });
  if (response.status !== 200) return null;
  const cookie = response.headers.get("set-cookie");
  return {
    label: identity.label,
    role: identity.role,
    cookie: cookie ? cookie.split(";")[0] : null,
    session: response.body?.session ?? null
  };
}

/** `GET /api/orders/:id` becomes a concrete path with the identifier filled in. */
function concreteRoute(route, identifier) {
  const [, pathTemplate] = splitRoute(route);
  return pathTemplate.replace(/:([A-Za-z_][A-Za-z0-9_]*)/g, String(identifier)).replace(/\*/g, String(identifier));
}

function splitRoute(route) {
  const match = /^([A-Z]+)\s+(\/.*)$/.exec(route ?? "");
  if (match) return [match[1], match[2]];
  return ["GET", route?.startsWith("/") ? route : "/"];
}

function hasParameter(route) {
  return /[:*]/.test(splitRoute(route)[1]);
}

/**
 * Identifiers to try for a parameterised route, in the order a careful tester
 * would: the caller's own record first, so a 200 on someone else's is meaningful.
 */
function candidateIdentifiers(body) {
  const found = new Set();
  const walk = (node, depth = 0) => {
    if (depth > 4 || node === null || node === undefined) return;
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
      return;
    }
    if (typeof node === "object") {
      for (const [key, value] of Object.entries(node)) {
        if (/^id$/i.test(key) && (typeof value === "number" || typeof value === "string")) found.add(value);
        walk(value, depth + 1);
      }
    }
  };
  walk(body);
  return [...found];
}

/* ---------- per-category probes ---------- */

/**
 * Each probe returns `{ outcome, description, location }`.
 *
 * `outcome` is "verified" when the behaviour was observed, "refuted" when the
 * application demonstrably refused it, and "unsettled" when the probe could not
 * be run — a missing route, an unavailable identity, or a category that no safe
 * request can decide. "unsettled" is deliberately not a refutation: a static
 * candidate nobody could test stays `needs_review`, which is the honest state.
 */
const PROBES = {
  async broken_object_level_authorization({ baseUrl, finding, sessions }) {
    const route = finding.affected.route;
    if (!route || !hasParameter(route)) return unsettled("The route has no identifier parameter to vary.");
    const [method, pathTemplate] = splitRoute(route);
    if (method !== "GET") return unsettled(`Only GET routes are probed for cross-account reads; this route is ${method}.`);

    const a = sessions.find((session) => session.role !== "admin");
    const b = sessions.find((session) => session !== a && session.role !== "admin");
    if (!a || !b) return unsettled("Two non-administrative identities were not available.");

    // Discover each identity's own records rather than guessing identifiers.
    const collection = pathTemplate.replace(/\/[:*][^/]*$/, "");
    const ownedByB = await listOwned(baseUrl, collection, b);
    if (ownedByB.length === 0) return unsettled(`No records were listed for ${b.label} under ${collection}.`);

    for (const identifier of ownedByB) {
      const probe = await request(`${baseUrl}${concreteRoute(route, identifier)}`, {
        headers: a.cookie ? { cookie: a.cookie } : {}
      });
      if (probe.status === 200 && probe.text.length > 2) {
        return {
          outcome: "verified",
          kind: "identity_differential",
          description: `Signed in as ${a.label} and requested ${concreteRoute(route, identifier)}, a record listed for ${b.label}. The response was HTTP 200 with a body of ${probe.text.length} bytes.`,
          location: `${method} ${concreteRoute(route, identifier)}`
        };
      }
    }
    return {
      outcome: "refuted",
      description: `Requested ${ownedByB.length} record(s) belonging to ${b.label} while signed in as ${a.label}; every response refused the read.`
    };
  },

  async broken_function_level_authorization({ baseUrl, finding, sessions }) {
    const route = finding.affected.route;
    if (!route) return unsettled("No route was attributed to this candidate.");
    const [method, pathTemplate] = splitRoute(route);
    if (method !== "GET") return unsettled(`Only GET routes are probed unauthenticated; this route is ${method}.`);

    const ordinary = sessions.find((session) => session.role !== "admin");
    const asAnonymous = await request(`${baseUrl}${pathTemplate}`);
    if (asAnonymous.status === 200) {
      return {
        outcome: "verified",
        kind: "runtime",
        description: `Requested ${pathTemplate} with no session at all and received HTTP 200 with a body of ${asAnonymous.text.length} bytes.`,
        location: route
      };
    }
    if (ordinary) {
      const asUser = await request(`${baseUrl}${pathTemplate}`, {
        headers: ordinary.cookie ? { cookie: ordinary.cookie } : {}
      });
      if (asUser.status === 200) {
        return {
          outcome: "verified",
          kind: "identity_differential",
          description: `Requested ${pathTemplate} as ${ordinary.label}, whose role is ${ordinary.role ?? "unspecified"}, and received HTTP 200 with a body of ${asUser.text.length} bytes.`,
          location: route
        };
      }
      return {
        outcome: "refuted",
        description: `${pathTemplate} returned HTTP ${asAnonymous.status} unauthenticated and HTTP ${asUser.status} as ${ordinary.label}.`
      };
    }
    return unsettled(`No signed-in identity was available; unauthenticated access returned HTTP ${asAnonymous.status}.`);
  },

  async debug_endpoint_exposure(input) {
    return PROBES.broken_function_level_authorization(input);
  },

  async reflected_cross_site_scripting({ baseUrl, finding }) {
    const route = finding.affected.route;
    if (!route) return unsettled("No route was attributed to this candidate.");
    const [method, pathTemplate] = splitRoute(route);
    if (method !== "GET") return unsettled(`Reflection is probed on GET routes; this route is ${method}.`);

    const probe = await request(`${baseUrl}${pathTemplate}?q=${encodeURIComponent(XSS_PROBE)}`);
    if (probe.text.includes(XSS_PROBE)) {
      return {
        outcome: "verified",
        kind: "runtime",
        description: `Requested ${pathTemplate} with a markup probe in the q parameter; the response contained the probe unescaped, so the caller controls markup in the document.`,
        location: route
      };
    }
    if (probe.status === 200 && probe.text.includes("&lt;")) {
      return { outcome: "refuted", description: `The probe was returned escaped, so the response is not injectable through q.` };
    }
    return unsettled(`The route returned HTTP ${probe.status} and the probe did not appear in either form.`);
  },

  async path_traversal({ baseUrl, finding }) {
    const route = finding.affected.route;
    if (!route) return unsettled("No route was attributed to this candidate.");
    const [method, pathTemplate] = splitRoute(route);
    if (method !== "GET") return unsettled(`Containment is probed on GET routes; this route is ${method}.`);

    const attempts = [];
    for (const parameter of ["name", "file", "path", "filename"]) {
      for (const target of TRAVERSAL_TARGETS) {
        const probe = await request(`${baseUrl}${pathTemplate}?${parameter}=${encodeURIComponent(target)}`);
        attempts.push({ parameter, target, status: probe.status, text: probe.text });

        // Content came back: the read escaped its base directory.
        if (probe.status === 200 && probe.text.length > 2) {
          return {
            outcome: "verified",
            kind: "runtime",
            description: `Requested ${pathTemplate} with ${parameter}=${target} and received HTTP 200 with a body of ${probe.text.length} bytes, so the path is not contained to its base directory.`,
            location: route
          };
        }

        // A failure that names a path outside the base directory proves the
        // traversal resolved, even though the file happened not to exist. A 404
        // is otherwise indistinguishable from a correctly contained route, and
        // treating it as containment refutes a real vulnerability.
        const escaped = escapedPathIn(probe.text, target);
        if (escaped) {
          return {
            outcome: "verified",
            kind: "runtime",
            description: `Requested ${pathTemplate} with ${parameter}=${target}. The response reported a failure against ${escaped}, which is outside the route's base directory, so the traversal resolved and only the absence of that file prevented the read.`,
            location: route
          };
        }
      }
    }

    // Only an explicit refusal counts as containment. Everything else is a
    // question the probe could not answer.
    const refusals = attempts.filter((attempt) => attempt.status === 403 || attempt.status === 400);
    if (refusals.length === attempts.length && attempts.length > 0) {
      return {
        outcome: "refuted",
        description: `Every traversal sequence was refused with HTTP ${refusals[0].status}, so the route enforces containment.`
      };
    }
    return unsettled(
      `Traversal attempts returned ${[...new Set(attempts.map((attempt) => attempt.status))].join(", ")} with no content and no resolved path in the response, so containment could not be settled.`
    );
  },

  async unsafe_query_composition({ baseUrl, finding }) {
    const route = finding.affected.route;
    if (!route) return unsettled("No route was attributed to this candidate.");
    const [method, pathTemplate] = splitRoute(route);
    if (method !== "GET") return unsettled(`Query composition is probed on GET routes; this route is ${method}.`);

    const benign = await request(`${baseUrl}${pathTemplate}?q=${encodeURIComponent("zzzz-no-such-term")}`);
    const widened = await request(`${baseUrl}${pathTemplate}?q=${encodeURIComponent(PREDICATE_PROBE)}`);
    const benignRows = rowCount(benign.body);
    const widenedRows = rowCount(widened.body);
    if (benignRows !== null && widenedRows !== null && widenedRows > benignRows) {
      return {
        outcome: "verified",
        kind: "runtime",
        description: `A term that matches nothing returned ${benignRows} row(s); the same route with a predicate terminator returned ${widenedRows}. The caller therefore controls the structure of the query, not only the value matched.`,
        location: route
      };
    }
    if (benignRows !== null && widenedRows !== null) {
      return {
        outcome: "refuted",
        description: `The predicate terminator returned ${widenedRows} row(s) against ${benignRows} for a non-matching term, so the value is not interpreted as part of the query.`
      };
    }
    return unsettled(`The route returned HTTP ${widened.status} with no countable result set.`);
  },

  async business_logic_price_manipulation({ baseUrl, finding, sessions, check }) {
    const route = finding.affected.route;
    if (!route) return unsettled("No route was attributed to this candidate.");
    const [method, pathTemplate] = splitRoute(route);
    if (method !== "POST") return unsettled(`Only POST routes are probed for value manipulation; this route is ${method}.`);

    const buyer = sessions.find((session) => session.role !== "admin");
    if (!buyer) return unsettled("No signed-in identity was available to submit the request.");

    // A negative quantity is a value probe, not a destructive act, but it does
    // create a record — so it goes through the safety gate first.
    const allowed = await check({
      intent: "submit_negative_quantity_to_measure_price_validation",
      description: `Send quantity -1 to ${route} once, as a test identity, to establish whether the total is bounded.`,
      method: "POST",
      target: `${baseUrl}${pathTemplate}`
    });
    if (!allowed) return unsettled("The safety gate declined the value probe, so this candidate stays unsettled.");

    const probe = await request(`${baseUrl}${pathTemplate}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(buyer.cookie ? { cookie: buyer.cookie } : {}) },
      body: JSON.stringify({ productId: 1, quantity: -1 })
    });
    const total = findNumber(probe.body, /total|amount|price|sum|charge/i);
    if (probe.status < 400 && total !== null && total < 0) {
      return {
        outcome: "verified",
        kind: "runtime",
        description: `Submitted quantity -1 to ${pathTemplate} as ${buyer.label}; the request succeeded with HTTP ${probe.status} and a total of ${total}. Nothing bounds the caller's quantity.`,
        location: route
      };
    }
    if (probe.status >= 400) {
      return { outcome: "refuted", description: `Quantity -1 was rejected with HTTP ${probe.status}.` };
    }
    return unsettled(`The response carried no recognisable total; HTTP ${probe.status}.`);
  },

  async weak_session_identifier({ baseUrl, identities }) {
    const first = await login(baseUrl, identities[0]);
    await delay(5);
    const second = await login(baseUrl, identities[0]);
    if (!first?.session || !second?.session) return unsettled("The login route did not return a session value to compare.");
    if (first.session === second.session) {
      return {
        outcome: "verified",
        kind: "runtime",
        description: "Two consecutive logins for the same identity produced an identical session value, so the identifier is not drawn from a random source.",
        location: "POST /api/login"
      };
    }
    const shared = commonPrefix(first.session, second.session);
    if (shared >= 8) {
      return {
        outcome: "verified",
        kind: "runtime",
        description: `Two consecutive logins produced session values sharing a ${shared}-character prefix, which a cryptographic source would not do.`,
        location: "POST /api/login"
      };
    }
    return unsettled(
      `Two logins produced distinct values with no shared prefix; predictability could not be settled from two samples without knowing the generator.`
    );
  },

  async verbose_error_response({ baseUrl, finding }) {
    const route = finding.affected.route;
    const [, pathTemplate] = splitRoute(route ?? "GET /");
    // Force a parse failure rather than a destructive action.
    const probe = await request(`${baseUrl}${pathTemplate}?q=${encodeURIComponent("%%%")}`, {
      headers: { accept: "application/json" }
    });
    if (/\bat\s+\S+:\d+:\d+|\/node_modules\/|\.js:\d+/.test(probe.text)) {
      return {
        outcome: "verified",
        kind: "runtime",
        description: `The response to ${pathTemplate} contained a stack trace with file paths and line numbers.`,
        location: route ?? pathTemplate
      };
    }
    return unsettled("No handled failure could be triggered safely on this route.");
  },

  async server_side_request_forgery({ baseUrl, finding, sessions, check }) {
    const route = finding.affected.route;
    if (!route) return unsettled("No route was attributed to this candidate.");
    const [method, pathTemplate] = splitRoute(route);
    if (method !== "POST") return unsettled(`Outbound fetch is probed on POST routes; this route is ${method}.`);

    const caller = sessions.find((session) => session.role !== "admin") ?? null;
    // The destination is the fixture's own origin. Pointing this probe anywhere
    // else would be an attack on somebody else's infrastructure.
    const destination = `${baseUrl}/api/products`;
    const allowed = await check({
      intent: "request_project_owned_origin_through_import_route",
      description: `Ask ${route} to fetch ${destination}, which is the fixture's own origin, to establish whether the destination is validated.`,
      method: "POST",
      target: `${baseUrl}${pathTemplate}`
    });
    if (!allowed) return unsettled("The safety gate declined the outbound probe, so this candidate stays unsettled.");

    const probe = await request(`${baseUrl}${pathTemplate}`, {
      method: "POST",
      headers: { "content-type": "application/json", ...(caller?.cookie ? { cookie: caller.cookie } : {}) },
      body: JSON.stringify({ url: destination })
    });
    if (probe.status < 400) {
      return {
        outcome: "verified",
        kind: "runtime",
        description: `${route} fetched a destination supplied entirely by the caller and returned HTTP ${probe.status}. No allowlist was consulted, so the destination is the caller's choice.`,
        location: route
      };
    }
    return { outcome: "refuted", description: `The caller-supplied destination was refused with HTTP ${probe.status}.` };
  },

  async insecure_cookie_configuration({ baseUrl, identities }) {
    const response = await request(`${baseUrl}/api/login`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: identities[0].email, password: identities[0].password })
    });
    const cookie = response.headers.get("set-cookie");
    if (!cookie) return unsettled("The login route set no cookie to inspect.");
    const missing = ["HttpOnly", "Secure", "SameSite"].filter(
      (attribute) => !new RegExp(attribute, "i").test(cookie)
    );
    if (missing.length > 0) {
      return {
        outcome: "verified",
        kind: "runtime",
        description: `The session cookie returned by the login route is missing ${missing.join(", ")}.`,
        location: "POST /api/login"
      };
    }
    return { outcome: "refuted", description: "The session cookie carries HttpOnly, Secure, and SameSite." };
  }
};

/**
 * A path outside the route's base directory, named by an error message. Node's
 * file errors quote the absolute path they tried, which is the clearest possible
 * evidence that a traversal resolved.
 */
function escapedPathIn(text, target) {
  const tail = target.replace(/\.\.[/%2f]*/gi, "").replace(/^\/+/, "");
  if (tail.length === 0) return null;
  const escapedTail = tail.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const match = new RegExp(`(/[^\\s'"]*${escapedTail})`).exec(text);
  return match ? match[1] : null;
}

function unsettled(reason) {
  return { outcome: "unsettled", description: reason };
}

function rowCount(body) {
  if (!body || typeof body !== "object") return null;
  for (const value of Object.values(body)) {
    if (Array.isArray(value)) return value.length;
  }
  return null;
}

function findNumber(body, namePattern) {
  if (!body || typeof body !== "object") return null;
  let found = null;
  const walk = (node, depth = 0) => {
    if (found !== null || depth > 4 || !node || typeof node !== "object") return;
    for (const [key, value] of Object.entries(node)) {
      if (typeof value === "number" && namePattern.test(key)) {
        found = value;
        return;
      }
      walk(value, depth + 1);
    }
  };
  walk(body);
  return found;
}

function commonPrefix(a, b) {
  let index = 0;
  while (index < a.length && index < b.length && a[index] === b[index]) index += 1;
  return index;
}

/** Identifiers the given identity can see under a collection route. */
async function listOwned(baseUrl, collection, session) {
  for (const path of [collection, `${collection}/mine`, `${collection}?mine=1`]) {
    const response = await request(`${baseUrl}${path}`, {
      headers: session.cookie ? { cookie: session.cookie } : {}
    });
    if (response.status !== 200) continue;
    const identifiers = candidateIdentifiers(response.body);
    if (identifiers.length > 0) return identifiers;
  }
  // Fall back to the identity's own profile, which often names its records.
  const me = await request(`${baseUrl}/api/me`, { headers: session.cookie ? { cookie: session.cookie } : {} });
  return candidateIdentifiers(me.body);
}

/**
 * Settle every candidate the static pass recorded.
 *
 * `check` gates any probe with a side effect through the CLI's own action policy,
 * so a refusal is recorded as an unsettled candidate rather than worked around.
 */
export async function validate({ baseUrl, findings, identities, check }) {
  const sessions = [];
  for (const identity of identities) {
    const session = await login(baseUrl, identity);
    if (session) sessions.push(session);
  }

  const outcomes = [];
  const notes = { coverage: [], limitations: [] };

  if (sessions.length < 2) {
    notes.limitations.push(
      `Only ${sessions.length} test identity signed in, so cross-account comparisons could not be completed.`
    );
  } else {
    notes.coverage.push(
      `Cross-account behaviour was compared using ${sessions.length} signed-in test identities against the running application.`
    );
  }

  for (const finding of findings) {
    const probe = PROBES[finding.category];
    if (!probe) {
      outcomes.push({
        findingId: finding.id,
        category: finding.category,
        outcome: "unsettled",
        description: `No safe runtime probe exists for ${finding.category}; it stays as the static pass reported it.`
      });
      continue;
    }
    try {
      const result = await probe({ baseUrl, finding, sessions, identities, check });
      outcomes.push({ findingId: finding.id, category: finding.category, ...result });
    } catch (error) {
      outcomes.push({
        findingId: finding.id,
        category: finding.category,
        outcome: "unsettled",
        description: `The probe failed to run: ${error instanceof Error ? error.message : "unknown error"}`
      });
    }
  }

  const unsettled = outcomes.filter((outcome) => outcome.outcome === "unsettled");
  if (unsettled.length > 0) {
    notes.limitations.push(
      `${unsettled.length} candidate(s) could not be settled against the running application and remain as the static pass reported them.`
    );
  }

  return { outcomes, notes, identitiesUsed: sessions.map((session) => session.label) };
}

export { PROBES };
