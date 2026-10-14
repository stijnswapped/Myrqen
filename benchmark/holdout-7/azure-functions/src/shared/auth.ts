import { HttpRequest, HttpResponseInit, InvocationContext } from "@azure/functions";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { SiteMemberDocument, container } from "./cosmos.js";

/**
 * Caller identity for the Sitewatch API.
 *
 * Supervisors and contractors sign in to the SPA with MSAL against their own Entra ID
 * tenant and call us with an access token for api://sitewatch. This module is the only
 * place that is allowed to decide who the caller is.
 */

const ENTRA_API_AUDIENCE = process.env.ENTRA_API_AUDIENCE ?? "api://sitewatch";
const ENTRA_JWKS_URI =
  process.env.ENTRA_JWKS_URI ?? "https://login.microsoftonline.com/common/discovery/v2.0/keys";
const ONBOARDED_TENANTS = (process.env.ENTRA_ONBOARDED_TENANTS ?? "")
  .split(",")
  .map((value) => value.trim())
  .filter(Boolean);

const jwks = createRemoteJWKSet(new URL(ENTRA_JWKS_URI));

export interface CallerClaims {
  oid: string;
  tid: string;
  username: string;
  roles: string[];
  groups: string[];
  scopes: string[];
}

export class AuthError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "AuthError";
    this.status = status;
  }
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [];
}

/**
 * Validates the bearer token and returns the claims we care about. Multi-tenant app, so
 * the issuer is not a constant: we check that the token was issued by the very tenant it
 * claims to belong to, and that we have onboarded that tenant.
 */
export async function verifyAccessToken(request: HttpRequest): Promise<CallerClaims> {
  const header = request.headers.get("authorization") ?? "";
  if (!/^bearer\s+/i.test(header)) {
    throw new AuthError(401, "An Entra ID bearer token is required");
  }

  const token = header.replace(/^bearer\s+/i, "").trim();
  let payload: Record<string, unknown>;
  try {
    const verified = await jwtVerify(token, jwks, {
      audience: ENTRA_API_AUDIENCE,
      algorithms: ["RS256"],
      clockTolerance: 30,
    });
    payload = verified.payload as Record<string, unknown>;
  } catch {
    throw new AuthError(401, "The access token could not be validated");
  }

  const oid = typeof payload.oid === "string" ? payload.oid : "";
  const tid = typeof payload.tid === "string" ? payload.tid : "";
  if (!oid || !tid) {
    throw new AuthError(401, "The access token is missing oid or tid");
  }
  if (payload.iss !== `https://login.microsoftonline.com/${tid}/v2.0`) {
    throw new AuthError(401, "The token issuer does not match its tenant claim");
  }
  if (ONBOARDED_TENANTS.length > 0 && !ONBOARDED_TENANTS.includes(tid)) {
    throw new AuthError(403, "That Entra tenant has not been onboarded");
  }

  return {
    oid,
    tid,
    username: typeof payload.preferred_username === "string" ? payload.preferred_username : "",
    roles: stringArray(payload.roles),
    groups: stringArray(payload.groups),
    scopes: typeof payload.scp === "string" ? payload.scp.split(" ") : [],
  };
}

export function requireRole(caller: CallerClaims, ...roles: string[]): void {
  if (!roles.some((role) => caller.roles.includes(role))) {
    throw new AuthError(403, `This operation requires one of: ${roles.join(", ")}`);
  }
}

export interface ClientPrincipalClaim {
  typ: string;
  val: string;
}

export interface ClientPrincipal {
  authType: string;
  claims: ClientPrincipalClaim[];
  roles: string[];
  objectId?: string;
  tenantId?: string;
  displayName?: string;
}

const OID_CLAIM = "http://schemas.microsoft.com/identity/claims/objectidentifier";
const TID_CLAIM = "http://schemas.microsoft.com/identity/claims/tenantid";
const NAME_CLAIM = "name";

/**
 * Decodes the x-ms-client-principal header. Note what this is: base64-encoded JSON that
 * App Service Authentication puts on the request after it has validated the token itself.
 * Nothing in here is signed, so it is only worth anything while Easy Auth is enabled and
 * is the thing terminating the request.
 */
export function readClientPrincipal(request: HttpRequest): ClientPrincipal | undefined {
  const encoded = request.headers.get("x-ms-client-principal");
  if (!encoded) {
    return undefined;
  }
  try {
    const decoded = JSON.parse(Buffer.from(encoded, "base64").toString("utf8")) as {
      auth_typ?: string;
      claims?: ClientPrincipalClaim[];
      role_typ?: string;
    };
    const claims = Array.isArray(decoded.claims) ? decoded.claims : [];
    const roleType = decoded.role_typ ?? "roles";
    return {
      authType: decoded.auth_typ ?? "aad",
      claims,
      roles: claims.filter((claim) => claim.typ === roleType).map((claim) => claim.val),
      objectId: claims.find((claim) => claim.typ === OID_CLAIM)?.val,
      tenantId: claims.find((claim) => claim.typ === TID_CLAIM)?.val,
      displayName: claims.find((claim) => claim.typ === NAME_CLAIM)?.val,
    };
  } catch {
    return undefined;
  }
}

/**
 * Site membership is the real authorisation boundary in this product: an Entra role says
 * what kind of user you are, a membership row says which sites you may touch.
 */
export async function resolveSiteMembership(
  tenantId: string,
  siteId: string,
  principalId: string,
): Promise<SiteMemberDocument | undefined> {
  const { resources } = await container("siteMembers")
    .items.query<SiteMemberDocument>(
      {
        query:
          "SELECT * FROM c WHERE c.tenantId = @tenantId AND c.siteId = @siteId AND c.principalId = @principalId",
        parameters: [
          { name: "@tenantId", value: tenantId },
          { name: "@siteId", value: siteId },
          { name: "@principalId", value: principalId },
        ],
      },
      { partitionKey: tenantId },
    )
    .fetchAll();
  return resources[0];
}

export async function listSiteMemberships(caller: CallerClaims): Promise<SiteMemberDocument[]> {
  const { resources } = await container("siteMembers")
    .items.query<SiteMemberDocument>(
      {
        query: "SELECT * FROM c WHERE c.tenantId = @tenantId AND c.principalId = @principalId",
        parameters: [
          { name: "@tenantId", value: caller.tid },
          { name: "@principalId", value: caller.oid },
        ],
      },
      { partitionKey: caller.tid },
    )
    .fetchAll();
  return resources;
}

export function toHttpError(error: unknown, context: InvocationContext): HttpResponseInit {
  if (error instanceof AuthError) {
    return { status: error.status, jsonBody: { error: error.message } };
  }
  context.error("unhandled failure in handler", error);
  return { status: 500, jsonBody: { error: "Internal error" } };
}
