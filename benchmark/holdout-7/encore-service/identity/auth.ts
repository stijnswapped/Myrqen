import { APIError, Gateway, Header } from "encore.dev/api";
import { authHandler } from "encore.dev/auth";
import { createHmac, timingSafeEqual } from "node:crypto";
import { ridgeline } from "./db";

export type MemberRole = "owner" | "dispatcher" | "technician" | "viewer";

/**
 * What every endpoint with `auth: true` gets back from `getAuthData()`.
 * `orgID` and `role` come out of the membership row the session points at,
 * never out of the request, so handlers can treat them as the tenant and the
 * privilege level of the caller.
 */
export interface AuthData {
  userID: string;
  orgID: string;
  role: MemberRole;
  email: string;
}

interface AuthParams {
  authorization: Header<"Authorization">;
}

interface SessionRow {
  membership_id: string;
  user_id: string;
  org_id: string;
  role: MemberRole;
  email: string;
  expires_at: Date;
}

const sessionSecret = process.env.RIDGELINE_SESSION_SECRET ?? "";

function sign(sessionID: string): string {
  return createHmac("sha256", sessionSecret).update(sessionID).digest("hex");
}

function macMatches(sessionID: string, provided: string): boolean {
  const expected = Buffer.from(sign(sessionID), "utf8");
  const actual = Buffer.from(provided, "utf8");
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

export const auth = authHandler<AuthParams, AuthData>(async (params) => {
  const token = params.authorization.replace(/^Bearer\s+/i, "").trim();
  const [sessionID, mac] = token.split(".");
  if (!sessionID || !mac) {
    throw APIError.unauthenticated("malformed session token");
  }
  if (!macMatches(sessionID, mac)) {
    throw APIError.unauthenticated("bad session signature");
  }

  const session = await ridgeline.queryRow<SessionRow>`
    select s.membership_id,
           m.user_id,
           m.org_id,
           m.role,
           u.email,
           s.expires_at
    from sessions s
    join memberships m on m.id = s.membership_id
    join users u on u.id = m.user_id
    where s.id = ${sessionID}
      and s.revoked_at is null
      and m.deactivated_at is null
  `;
  if (!session) {
    throw APIError.unauthenticated("unknown session");
  }
  if (session.expires_at.getTime() <= Date.now()) {
    throw APIError.unauthenticated("session expired");
  }

  return {
    userID: session.user_id,
    orgID: session.org_id,
    role: session.role,
    email: session.email,
  };
});

export const gateway = new Gateway({ authHandler: auth });
