import net from "node:net";

export interface NormalizedTarget {
  input: string;
  origin: string;
  hostname: string;
  port: string;
  protocol: string;
  /** True only for machine-local hosts. Private LAN ranges are NOT local. */
  local: boolean;
  /** RFC1918 / CGNAT / link-local. Requires explicit authorization like any external host. */
  privateNetwork: boolean;
}

const DOCKER_HOST_ALIASES = new Set(["host.docker.internal", "gateway.docker.internal", "docker.for.mac.localhost"]);

function isLoopbackHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (host === "localhost" || host.endsWith(".localhost")) return true;
  if (host === "::1" || host === "0:0:0:0:0:0:0:1") return true;
  if (DOCKER_HOST_ALIASES.has(host)) return true;
  if (net.isIP(host) === 4) return host.split(".")[0] === "127";
  return false;
}

function isPrivateNetworkHost(hostname: string): boolean {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (net.isIP(host) === 4) {
    const parts = host.split(".").map(Number);
    const a = parts[0] ?? 0;
    const b = parts[1] ?? 0;
    if (a === 10) return true;
    if (a === 192 && b === 168) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 0) return true;
    return false;
  }
  if (net.isIP(host) === 6) {
    return host.startsWith("fc") || host.startsWith("fd") || host.startsWith("fe80");
  }
  if (host.endsWith(".local") || host.endsWith(".internal") || host.endsWith(".lan")) return true;
  return false;
}

export function normalizeHttpTarget(input: string): NormalizedTarget {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new Error(`"${input}" is not a valid absolute http(s) URL.`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http/https application targets are supported by this policy helper.");
  }
  url.username = "";
  url.password = "";
  url.hash = "";
  const hostname = url.hostname.toLowerCase();
  return {
    input,
    origin: url.origin,
    hostname,
    port: url.port,
    protocol: url.protocol,
    local: isLoopbackHost(hostname),
    privateNetwork: isPrivateNetworkHost(hostname)
  };
}

export function requiresExternalAuthorization(input: string): boolean {
  return !normalizeHttpTarget(input).local;
}

export function exactOriginAuthorized(input: string, authorizedOrigins: Iterable<string>): boolean {
  const target = normalizeHttpTarget(input);
  if (target.local) return true;
  const allowed = new Set<string>();
  for (const value of authorizedOrigins) {
    try {
      allowed.add(normalizeHttpTarget(value).origin);
    } catch {
      // A malformed stored origin must never widen scope.
    }
  }
  return allowed.has(target.origin);
}

export class ScopeViolationError extends Error {
  readonly origin: string;
  constructor(origin: string) {
    super(
      `External target ${origin} is not authorized. Authorization is per exact origin: scheme, host, and port must match.`
    );
    this.name = "ScopeViolationError";
    this.origin = origin;
  }
}

export function assertNoScopeExpansion(input: string, authorizedOrigins: Iterable<string>): void {
  if (!exactOriginAuthorized(input, authorizedOrigins)) {
    throw new ScopeViolationError(normalizeHttpTarget(input).origin);
  }
}

export type RedirectDecision =
  | { decision: "follow"; reason: "same_origin" | "authorized_origin" }
  | { decision: "block"; reason: "crosses_authorization_boundary"; origin: string };

/** Redirects that leave the authorized origin set are gated, never followed blindly. */
export function classifyRedirect(
  fromUrl: string,
  toUrl: string,
  authorizedOrigins: Iterable<string>
): RedirectDecision {
  const from = normalizeHttpTarget(fromUrl);
  const to = normalizeHttpTarget(toUrl);
  if (from.origin === to.origin) return { decision: "follow", reason: "same_origin" };
  if (to.local && from.local) return { decision: "follow", reason: "same_origin" };
  if (exactOriginAuthorized(to.origin, authorizedOrigins)) {
    return { decision: "follow", reason: "authorized_origin" };
  }
  return { decision: "block", reason: "crosses_authorization_boundary", origin: to.origin };
}

export interface ExternalTargetPosture {
  maxConcurrency: number;
  minDelayMs: number;
  allowedMethods: readonly string[];
  followCrossOriginRedirects: false;
  stopOnProductionIndicators: true;
}

/** External targets stay under stricter rules even after the user authorizes them. */
export function externalTargetPosture(): ExternalTargetPosture {
  return Object.freeze({
    maxConcurrency: 1,
    minDelayMs: 400,
    allowedMethods: Object.freeze(["GET", "HEAD", "OPTIONS"]),
    followCrossOriginRedirects: false,
    stopOnProductionIndicators: true
  });
}

export interface LocalTargetPosture {
  maxConcurrency: number;
  minDelayMs: number;
  allowedMethods: readonly string[];
}

export function localTargetPosture(maxConcurrency: number): LocalTargetPosture {
  return Object.freeze({
    maxConcurrency,
    minDelayMs: 0,
    allowedMethods: Object.freeze(["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"])
  });
}

export function buildAuthorizationPrompt(origin: string): string {
  return `This project calls ${origin}. Only continue dynamic testing if you own it or have permission to test it. Authorize this exact target? [y/N]`;
}

export function describeScopeRefusal(origin: string, authorized: readonly string[]): string {
  const list = authorized.length > 0 ? authorized.join(", ") : "none";
  return [
    `${origin} is outside the authorized scope for this scan.`,
    `Authorized external origins: ${list}.`,
    "Authorization does not extend to parent domains, subdomains, sibling services, other ports, or IP ranges."
  ].join(" ");
}
